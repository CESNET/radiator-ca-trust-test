#!/usr/bin/perl -w

package CATrustTest;

use strict;
use Data::Dumper;
use Sys::Syslog;

my $maxTestTime = 30; # maximum time we will mess with any of our clients
my $reInitTime = 5*60; # how often check if there are new data in SQL database

# working variables
my $lastInitTime = 0;
my %known;
my %leaked;
my %persistent;

my $dbh;

my $CSI_default = '??:??:??:??:??:??';
my $username_default = 'unknown';

sub _syslog {
  sub escape {
    my $line = shift;

    $line =~ s,\:,\\\:,g;

    return $line;
  };

  #main::log($main::LOG_DEBUG, "CATrustTest: syslog");

  openlog('CATrustTest', 'cons,pid', 'local0');
  syslog('info', join(":", map {escape($_)} @_));
  closelog();
};


sub init {
  unless ($dbh) {
    $dbh = Radius::AuthGeneric::find('CATrustTestDB');
  };

  $lastInitTime = time;

  if ($dbh) {
    # load known clients from DB into memory
    my $query = 'SELECT MAX(timestamp) AS timestamp, mac FROM catt GROUP BY mac';
    my $sth = $dbh->prepareAndExecute($query);
    my $counter = 0;
    while (my $res = $sth->fetchrow_hashref) {
      $persistent{$res->{mac}} = $res->{timestamp};
      $counter++;
    };
    &main::log($main::LOG_DEBUG, "CATrustTest: loaded $counter CSI from SQL storage");
  } else {
    &main::log($main::LOG_DEBUG, "CATrustTest: failed to get \$dbh; is SQL storage defined?");
  };
};

sub reInit {
  my $now = time;

  unless ($dbh) {
    $dbh = Radius::AuthGeneric::find('CATrustTestDB');
  };
  return unless($dbh);

  if (($lastInitTime+$reInitTime) < $now) {
    my $query = 'SELECT timestamp, mac, username FROM catt WHERE username=\'CATrustTest\'';
    my $sth = $dbh->prepareAndExecute($query);
    my $res = $sth->fetchrow_hashref;

    if ($res) {
      if ($res->{timestamp} >= $lastInitTime) {
	init();
      } else {
	&main::log($main::LOG_DEBUG, "CATrustTest: no reason to call init again (".$res->{timestamp}." <= $now)");
      };
    } else {
      &main::log($main::LOG_DEBUG, "CATrustTest: failed to exec \"$query\"");
    };

    $lastInitTime = $now;
  };
};

sub cleanup {
  my $now = time;

  foreach my $CSI (keys %known) {
    if ($now > ($known{$CSI}->{timestamp}+$maxTestTime)) {
      recordTestResult($now, $CSI, $known{$CSI}->{username}, 'unknown');
      &main::log($main::LOG_DEBUG, "CATrustTest: client $CSI / ".$known{$CSI}->{username}." timeouted");
      delete $known{$CSI};
    };
  };

  return 1;
};

sub recordTestResult {
  my $now = shift;
  my $CSI = shift;
  my $user = shift;
  my $result = shift;

  unless ($dbh) {
    $dbh = Radius::AuthGeneric::find('CATrustTestDB');
  };

  $persistent{$CSI} = $now;

  if ($dbh) {
    my $query = sprintf("INSERT INTO catt (timestamp, username, mac, result) VALUES (%s, %s, %s, %s)",
			$now,
			$dbh->quote($user),
			$dbh->quote($CSI),
			$dbh->quote($result));
    #&main::log($main::LOG_DEBUG, "CATrustTest: $query");
    my $sth = $dbh->prepareAndExecute($query);
    _syslog("TIMESTAMP=$now#PN=$user#CSI=$CSI#RESULT=$result");
  } else {
    &main::log($main::LOG_DEBUG, "CATrustTest: failed to get \$dbh; is SQL storage defined?");
  };
};

sub normalizeMAC {
  my $mac = shift;

  return unless($mac);

  $mac =~ s/[\.\-:]//g;
  $mac = lc($mac);
  $mac =~ s/(.{12}).*$/$1/;
  $mac =~ s/(.{2})/$1-/g;
  $mac =~ s/-$//g;

  return $mac;
};

sub evaluateResult {
  my $p = ${$_[0]};
  my $rp = ${$_[1]};
  my $result = ${$_[2]};
  my $reason = ${$_[3]} || '';
  my $now = time;

  # This should be never called without those two attributes, as they
  # are tested in tagClient and client without them is never being
  # tested.
  my $CSI = normalizeMAC($p->get_attr('Calling-Station-Id')) || $CSI_default;
  my $user = $p->get_attr('User-Name') || $username_default;

  # Examples of $reasons we can get (on Radiator 4.17 patch 2001:
  # EAP PEAP TLS Handshake unsuccessful
  # EAP TTLS Handshake unsuccessful: 12741: 1 - error:14094418:SSL routines:SSL3_READ_BYTES:tlsv1 alert unknown ca

  if ($reason =~ /TLS Handshake unsuccessful/) {
    # client didn't accepted our fake CA.
    # move first seen time off period to permit quick recovery
    recordTestResult($now, $CSI, $user, 'CArefused');
    &main::log($main::LOG_DEBUG, "CATrustTest: client $CSI / $user refused fake CA");
  } elsif ($result == $main::ACCEPT || $result == $main::REJECT) {
    recordTestResult($now, $CSI, $user, 'CAaccepted');
    &main::log($main::LOG_DEBUG, "CATrustTest: client $CSI / $user leaked his password");

    # record info, that this client already leaked his password
    $leaked{$CSI}->{timestamp} = $now;
    $leaked{$CSI}->{username} = $user;
    delete $known{$CSI};
  };

  if ($result == $main::ACCEPT or $result == $main::REJECT) {
    ${$_[2]} = $main::REJECT;
  };
};

sub tagClient {
  my $p = ${$_[0]};

  # only Access-Request are relevant
  return unless ($p->code eq 'Access-Request');
  # only Access-Request with EAP Message
  return unless $p->get_attr('EAP-Message');

  #sleep(1);

  my $CSI = normalizeMAC($p->get_attr('Calling-Station-Id'));
  return unless($CSI);
  my $user = $p->get_attr('User-Name');
  return unless($user);

  if ((not ($user =~ /cesnet\.(cz|eu)$/i)) or
      ($CSI =~ /^70-6F-6C/i) or
      ($CSI =~ /^22-44-66-ca-20-01/i)) {
    &main::log($main::LOG_DEBUG, "CATrustTest: not testing client $CSI / $user; out of our jurisdiction or monitoring");
    return;
  };

  my $now = time;

  my $test = 1;

  if (exists $persistent{$CSI}) {
    $test = 0;
    #&main::log($main::LOG_DEBUG, "CATrustTest: client $CSI / $user was already tested in past before restart");
  } elsif (exists $leaked{$CSI}) {
    # client already leaked his password; do not mess his authentication anymore
    $test = 0;
  } elsif (exists $known{$CSI}) {
    # know client, test only if it is recent, it should be cleaned after some time in cleanup()
    $test = $now <= ($known{$CSI}->{timestamp}+$maxTestTime)
  } else {
    # we meet first time
    $known{$CSI}->{timestamp} = $now;
    $known{$CSI}->{username} = $user;
  };

  if ($test) {
    $p->add_attr('CESNET-CATrustTest', 'TEST');
    &main::log($main::LOG_DEBUG, "CATrustTest: testing client $CSI / $user");
    return;
  };

  &main::log($main::LOG_DEBUG, "CATrustTest: not testing already tested client $CSI / $user");
};

sub recordAuthResult {
  my $p = ${$_[0]};
  my $rp = ${$_[1]};
  my $result = ${$_[2]};

  if ($result == $main::ACCEPT) {
    my $CSI = normalizeMAC($p->get_attr('Calling-Station-Id'));
    return unless($CSI);
    my $user = $p->get_attr('User-Name');
    return unless($user);

    unless (exists $leaked{$CSI}) {
      &main::log($main::LOG_DEBUG, "CATrustTest: $CSI / $user got Access-Accept ... not leaked user");
      return;
    };
    if ($leaked{$CSI}->{success_aa}) {
      &main::log($main::LOG_DEBUG, "CATrustTest: $CSI / $user got Access-Accept - db was already updated");
      return;
    };

    unless ($dbh) {
      $dbh = Radius::AuthGeneric::find('CATrustTestDB');
    };

    if ($dbh) {
      my $now = time;

      my $query = sprintf("UPDATE catt SET success_aa=%s WHERE timestamp=%s AND username=%s AND mac=%s",
			  $now,
			  $leaked{$CSI}->{timestamp} || 0,
			  $dbh->quote($user),
			  $dbh->quote($CSI));
      $leaked{$CSI}->{success_aa} = $now;
      &main::log($main::LOG_DEBUG, "CATrustTest: $CSI / $user got Access-Accept - updating db");
      my $sth = $dbh->prepareAndExecute($query);

      _syslog("TIMESTAMP=".$leaked{$CSI}->{timestamp}."#PN=$user#CSI=$CSI#AUTHRESULT=ACCEPT");
    };
  };
};

sub stopTunnelledRequests {
  my $p = ${$_[0]};
  #my $rp = ${$_[1]};
  #my $result = ${$_[2]};

  if ($p->{tunnelledByPEAP} or
      $p->{tunnelledByTTLS} or
      $p->{tunnelledByFAST}) {

    my $CSI = normalizeMAC($p->get_attr('Calling-Station-Id')) || $CSI_default;
    my $user = $p->get_attr('User-Name') || $username_default;

    &main::log($main::LOG_DEBUG, "CATrustTest: rejecting tunnelled request for $CSI / $user");

    ${$_[2]} = $main::REJECT;
  };


  return 1;
};

init();

1;

