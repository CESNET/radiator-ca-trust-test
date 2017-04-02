#!/usr/bin/perl -w

use strict;
use DBI;
use Sys::Syslog;

$|=1;

sub _syslog {
  sub escape {
    my $line = shift;

    $line =~ s,\:,\\\:,g;

    return $line;
  };

  openlog('CATrustTest_receiver:', 'cons,pid', 'local0');
  syslog('info', join(":", map {escape($_)} @_));
  closelog();
};

# load DB params
my $DB;
my $db_user;
my $db_pswd;
open(CFG, '</etc/radiator/radius.cfg') or do {
  _syslog("Failed to open /etc/radiator/radius.cfg: ".$?);
  sleep 5; # sleep to not overload syslog server
  die("Failed to open /etc/radiator/radius.cfg: ".$?);
};
while (my $line=<CFG>) {
  if ($line =~ /DefineFormattedGlobalVar\s+CATrustTestDB\s+(\S+)/m) {
    $DB = $1;
  } elsif ($line =~ /DefineFormattedGlobalVar\s+CATrustTestUser\s+(\S+)/m) {
    $db_user = $1;
  } elsif ($line =~ /DefineFormattedGlobalVar\s+CATrustTestPswd\s+(\S+)/m) {
    $db_pswd = $1;
  };
};
close(CFG);

unless (($DB) and ($db_user) and ($db_pswd)) {
  _syslog("Failed to open read DB config from /etc/radiator/radius.cfg");
  sleep 5; # sleep to not overload syslog server
  die("Failed to open read DB config from /etc/radiator/radius.cfg");
};

my $dbh = DBI->connect($DB, $db_user, $db_pswd,
		       {RaiseError => 0, AutoCommit =>1, mysql_auto_reconnect=>1});

unless ($dbh) {
  _syslog("Failed to initalize SQL connection: Can't connect: ".$DBI::errstr);
  sleep 5; # sleep to not overload syslog server
  die "Can't connect: ".$DBI::errstr;
};

my $counter=0;
while (my $line = <>) {
  # TIMESTAMP=1490968208#PN=semik@semik-dev.cesnet.cz#CSI=60-D9-A0-60-B5-77#RESULT=CArefused
  if ($line =~ /TIMESTAMP=(\d+)#PN=(.+?)#CSI=(.+?)#RESULT=(.*)$/) {
    my $timestamp = $1;
    my $user = $2;
    my $csi = $3;
    my $result = $4;
    $counter++;

    my $query = sprintf("INSERT INTO catt (timestamp, username, mac, result) VALUES (%s, %s, %s, %s)",
			$timestamp,
			$dbh->quote($user),
			$dbh->quote($csi),
			$dbh->quote($result));
    $dbh->do($query);
    _syslog("Failed to exec \"$query\": ".$dbh->errmsg) if ($dbh->err);

    $query = sprintf("UPDATE catt SET timestamp=".time." WHERE username='CATrustTest'");
    $dbh->do($query);
    _syslog("Failed to exec \"$query\": ".$dbh->errmsg) if ($dbh->err);

    if (($counter <= 10) or ($counter % 100 == 0)) {
      _syslog("Received records: $counter");
    } elsif ($counter == 10) {
      _syslog("Received records: $counter. Next note on #100.");
    };

  };
};
