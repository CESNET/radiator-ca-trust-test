# Radiator-CA-Trust-Test

Set of Radiator hooks and example configuration file to show how to test if EAP clients are correctly checking if EAP server certificate is signed by trusted CA. Clients are distinguished by MAC address. First EAP authentication is handled by special EAP endpoint with wrong - self signed CA. Every following request is being handled by the right trusted CA. Attempts are recorded in log file and in MySQL storage.

If client is correctly configured than first EAP authentication fail because client refuses to send its credentials to rogue RADIUS. If client is incorrectly configured, RADIUS sends access-request.Surprisingly only Windows 7, 8 and 8.1 are not able to handle this technique and require user to re-enter his credentials. Following compatible systems, immediately retry authentication without requesting any action from user. Successfully tested systems are:
 * Android 4.4.4, 5.0.2, 6.0.1
 * iOS 10.2.1
 * Linux with wpa_supplicant: 1.0.3, 2.4.
 * Mac OS X 10.12.3 (Sierra)
 * Windows 10

# Setup

Hooks were developed with  Radiator RADIUS server 4.17 (patch set 1.2009), you will also need MySQL server and possibly syslog-ng server for remote synchronisation.

You are going to need database named and table catt (CATrustTest), see file [catt_sql_def](https://github.com/CESNET/radiator-ca-trust-test/blob/master/catt_sql_def). And you need to declare it in radius.cfg:
```
DefineFormattedGlobalVar CATrustTestDB	  DBI:mysql:radiator:localhost:3306
DefineFormattedGlobalVar CATrustTestUser	XXYYXX
DefineFormattedGlobalVar CATrustTestPswd	XXYYXX
<AuthBy SQL>
        Identifier      CATrustTestDB
        DBSource        %{GlobalVar:CATrustTestDB}
        DBUsername      %{GlobalVar:CATrustTestUser}
        DBAuth          %{GlobalVar:CATrustTestPswd}
</AuthBy>
```

Example configuration [radius.cfg](https://github.com/CESNET/radiator-ca-trust-test/blob/master/radius.cfg) contain complete configuration for RADIUS server handling realm @semik-dev.cesnet.cz. It is needed that you go through and adjust it for your needs. Search for XXYYXX, that are removed secrets or other private parameters you need to adjust to your needs.

You need at least two sets of certificates. You need some certificate from CA which isn't trusted in your organisation, it is used in ``AuthBy File`` with identifier ``trustTest``. And you need second certificate from trusted CA which is used in ``AuthBy LDAP2`` identified as ``CheckLDAP``. Maybe the could be same as CA your upstream RADIUS server trust and you can use it in ``ServerRADSEC``.

All hooks are implement as single Perl module [CATrustTest.pm](https://github.com/CESNET/radiator-ca-trust-test/blob/master/CATrustTest.pm) to allow simple integration with your existing Hooks. You need to load module during Radiator start up:
```
StartupHook	sub { require "/etc/radiator/CATrustTest.pm"; };
```
Function ``CATrustTest::tagClient()`` is used for marking clients which will be tested. As mark is used local attribute ``CESNET-CATrustTest==TEST``. See source code and adjust condition which clients will be subject of testing. Function ``CATrustTest::tagClient()`` need to be defined as hook on two places, first it need to be defined as ``PreClientHook`` if you wish to test all clients coming from all ``Client`` definitions. Second place is ``PreHandlerHook`` if you are using ``ServerRADSEC``.

You need to define special ``Handler`` which will catch all clients which are subject of test:
```
<Handler Realm=/.*/, CESNET-CATrustTest=TEST>
	AuthBy		    trustTest
	PostAuthHook	sub { CATrustTest::evaluateResult(@_) };
</Handler>
```
that handler has to be **before** your real working Handler. If you are not using regular expression in your real working Handler you have to start using them, otherwise they will precede testing handler, for example:
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
You maybe noted that there is no Handler 
```
<Handler Realm=/.*/, CESNET-CATrustTest=TEST, TunnelledByPEAP=1>
	AuthBy	CheckLDAP
</Handler>
```
that is because I was not able to figure any usable hook to catch inner tunnelled requests to tag them correctly. They are being catched in default Handler by function ``CATrustTest::stopTunnelledRequests()``. It is necessary to not pass them into working eduroam infrastructure. Example of default Handler:
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

The result of test is evaluated in function ``CATrustTest::evaluateResult()``, results are stored in table catt (CATrustTest), for example:
```
+------------+---------------------------+-------------------+------------+
| timestamp  | username                  | mac               | result     |
+------------+---------------------------+-------------------+------------+
| 1491121531 | semik@semik-dev.cesnet.cz | 8c-70-5a-20-d0-bc | CArefused  |
| 1491143917 | semik@semik-dev.cesnet.cz | 8c-99-e6-d8-6a-9d | CAaccepted |
+------------+---------------------------+-------------------+------------+
```
and also logged via syslog:
```
Apr  2 10:25:31 semik-dev CATrustTest[25026]: TIMESTAMP=1491121531#PN=semik@semik-dev.cesnet.cz#CSI=8c-70-5a-20-d0-bc#RESULT=CArefused
Apr  2 16:38:37 semik-dev CATrustTest[25026]: TIMESTAMP=1491143917#PN=semik@semik-dev.cesnet.cz#CSI=8c-99-e6-d8-6a-9d#RESULT=CAaccepted
```
