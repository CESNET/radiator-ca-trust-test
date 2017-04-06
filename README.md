# Radiator-CA-Trust-Test

This repository contains a set of Radiator hooks and an example configuration file to test EAP clients correct configuration, in this case whether clients are checking if the EAP server certificate is issued by a trusted Certificate Authority (CA). Clients are distinguished by MAC addresses. The first EAP authentication request is handled by a special EAP endpoint with a certificate issued by an untrusted self signed CA. All the following requests are handled by a trusted CA. All the attempts are recorded in a log file as well as in MySQL database.

If a client is configured correctly then the first EAP authentication request fails because the client refuses to send credentials to an untrusted RADIUS server. On the other hand, if the client is configured incorrectly, the RADIUS server sends `access-reject`. Surprisingly, only Windows 7, 8 and 8.1 are not able to handle this technique and ask the user to re-enter credentials. The following list of compatible systems immediately retry authentication without any user interaction.

Successfully tested systems:
- Android 4.4.4, 5.0.2, 6.0.1
- iOS 10.2.1, 10.3, 10.3.1
- Linux with wpa_supplicant: 1.0.3, 2.4.
- macOS Sierra 10.12.3, 10.12.4
- Windows 10

# Setup

Hooks are developed with Radiator RADIUS server 4.17 (patch set 1.2009), MySQL server for storing results and syslog-ng server for remote synchronisation.

A database named `radiator` with a table `catt` (*CATrustTest*) is required, see [catt_sql_def](https://github.com/CESNET/radiator-ca-trust-test/blob/master/catt_sql_def) file. To use this database, it has to be defined in `radius.cfg`:
```
DefineFormattedGlobalVar CATrustTestDB          DBI:mysql:radiator:localhost:3306
DefineFormattedGlobalVar CATrustTestUser        XXYYXX
DefineFormattedGlobalVar CATrustTestPswd        XXYYXX
<AuthBy SQL>
        Identifier      CATrustTestDB
        DBSource        %{GlobalVar:CATrustTestDB}
        DBUsername      %{GlobalVar:CATrustTestUser}
        DBAuth          %{GlobalVar:CATrustTestPswd}
</AuthBy>
```

An example configuration [radius.cfg](https://github.com/CESNET/radiator-ca-trust-test/blob/master/radius.cfg) file contains complete configuration for a RADIUS server handling `@semik-dev.cesnet.cz` realm. It is necessary to go through the file and adjust it for local environment. Search for the string `XXYYXX` and fill in appropriate information.

At least two sets of certificates are necessary. The first issued by a CA untrusted by your organization is used in `AuthBy File` with identifier `trustTest`. The second, on the other hand, issued by a CA trusted by your organization is used in ``AuthBy LDAP2`` identified as ``CheckLDAP``. This second certificate may be issued by the same CA your upstream RADIUS server trusts and you can use it in ``ServerRADSEC``.

All hooks are implemented as a single [CATrustTest.pm](https://github.com/CESNET/radiator-ca-trust-test/blob/master/CATrustTest.pm) Perl module to allow simple integration with your existing hooks. The module must be loaded during Radiator start up:
```
StartupHook	sub { require "/etc/radiator/CATrustTest.pm"; };
```
The function `CATrustTest::tagClient()` marks clients to be tested. The local attribute `CESNET-CATrustTest==TEST` is used as a mark. See source code and adjust the condition which clients will be subjects of the test if necessary. The function `CATrustTest::tagClient()` needs to be defined as a hook on two places. First, it has to be defined in `PreClientHook` if all clients coming from all `Client` definition have to be tested. Second, it has to be defined in `PreHandlerHook` if `ServerRADSEC` is employed.

A special `Handler` to catch all clients which are subjects of the test has to be defined:
```
<Handler Realm=/.*/, CESNET-CATrustTest=TEST>
	AuthBy		    trustTest
	PostAuthHook	sub { CATrustTest::evaluateResult(@_) };
</Handler>
```

This handler has to be **before** a real working `Handler`. You have to use regular expressions in the real working `Handler`, otherwise it will precede testing `Handler`, for example:
```
<Handler Realm=/^semik-dev\.cesnet\.cz$/, TunnelledByTTLS=1>
	AuthBy	CheckLDAP
</Handler>

<Handler Realm=/^semik-dev\.cesnet\.cz$/, TunnelledByPEAP=1>
	AuthBy	CheckLDAP
</Handler>

<Handler Realm=/^semik-dev\.cesnet\.cz$/>
	AuthBy	CheckLDAP
</Handler>
```

You may noticed that there is no `Handler`:
```
<Handler Realm=/.*/, CESNET-CATrustTest=TEST, TunnelledByPEAP=1>
	AuthBy	CheckLDAP
</Handler>
```
this is because I've been unable to figure any usable hook to catch inner tunnelled requests and to tag them correctly. They are catched by the default `Handler` by the function `CATrustTest::stopTunnelledRequests()`. It is necessary not to pass them into working *eduroam* infrastructure. Example of the default `Handler`:
```
<Handler> 
	AuthByPolicy	ContinueUntilReject
	<AuthBy INTERNAL>
		AuthResult    	IGNORE
		DefaultResult 	IGNORE
		PostAuthHook	sub { CATrustTest::stopTunnelledRequests(@_) };
	</AuthBy>
	...
```

# Output

The test results are evaluated by the `CATrustTest::evaluateResult()` function and then stored in the `catt` table (CATrustTest), for example:
```
+------------+---------------------------+-------------------+------------+
| timestamp  | username                  | mac               | result     |
+------------+---------------------------+-------------------+------------+
| 1491121531 | semik@semik-dev.cesnet.cz | 8c-70-5a-20-d0-bc | CArefused  |
| 1491143917 | semik@semik-dev.cesnet.cz | 8c-99-e6-d8-6a-9d | CAaccepted |
+------------+---------------------------+-------------------+------------+
```

Everything is also logged via syslog-ng:
```
Apr  2 10:25:31 semik-dev CATrustTest[25026]: TIMESTAMP=1491121531#PN=semik@semik-dev.cesnet.cz#CSI=8c-70-5a-20-d0-bc#RESULT=CArefused
Apr  2 16:38:37 semik-dev CATrustTest[25026]: TIMESTAMP=1491143917#PN=semik@semik-dev.cesnet.cz#CSI=8c-99-e6-d8-6a-9d#RESULT=CAaccepted
```

# DB Synchronization

In case you have multiple RADIUS servers you need to sychronize databases. I really do want to have our RADIUSes as independent as possible. That is the reason why I'm not using remote database for storing results. However, synchronisation is required to prevent running multiple tests on one client. Instead of using a remote database, I developed a simple synchronisation using syslog-ng. On both servers one just need to add the following code to syslog-ng:
```
source net {
  tcp(
    port(1999)
    tls( ca_dir("/etc/ssl/certs")
    key-file("/etc/ssl/private/radius1.cesnet.cz.key")
    cert-file("/etc/ssl/certs/radius1.cesnet.cz.crt"))
  );
};

destination net_catt { 
  file("/var/log/ca-trust-test-net" owner("root") group("adm") perm(0600));
  program("/etc/radiator/CATrustTest_receiver.pl");
};

destination d_catt {
  file("/var/log/ca-trust-test" owner("root") group("adm") perm(0640));

  tcp("radius2.cesnet.cz"
    port(1999) 
    tls( ca_dir("/etc/ssl/certs") 
    key_file("/etc/ssl/private/radius1.cesnet.cz.key")
    cert_file("/etc/ssl/certs/radius1.cesnet.cz.crt"))
  );
};

log { source(net); destination(net_catt); };
log { source(src); filter(f_catt); destination(d_catt); };
```

Remote syslog entries are stored within `cat-trust-test-net` file and syslog-ng forwards all the messages to [CATrustTest_receiver.pl](https://github.com/CESNET/radiator-ca-trust-test/blob/master/CATrustTest_receiver.pl) program. On every update, the receiver updates the timestamp on the record with username `CATrustTest` which is used by `CATrustTest::reInit()` function. This updates in-memory hash table of already tested clients. In case some entries are removed from the database the Radiator process has to be reloaded. Entries are only added automatically, but not removed.
