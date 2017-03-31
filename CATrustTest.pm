#!/usr/bin/perl -w

package CATrustTest;

use strict;
use Data::Dumper;

my $maxTestTime = 30; # maximum time we will mess with any of our clients
my %known;
my %leaked;
my %ignore;

sub evaluateResult {
  my $p = ${$_[0]};
  my $rp = ${$_[1]};
  my $result = ${$_[2]};
  my $reason = ${$_[3]} || '';
  my $now = time;

  my $CSI = $p->get_attr('Calling-Station-Id') || '??:??:??:??:??:??';
  my $user = $p->get_attr('User-Name') || 'undef';

  # EAP PEAP TLS Handshake unsuccessful
  # EAP TTLS Handshake unsuccessful: 12741: 1 - error:14094418:SSL routines:SSL3_READ_BYTES:tlsv1 alert unknown ca

  #&main::log($main::LOG_DEBUG, "CATrustTest: client $CSI / $user ???");

  if ($reason =~ /TLS Handshake unsuccessful/) {
    # client didn't accepted our fake CA.
    # move first seen time off period to permit quick recovery
    &main::log($main::LOG_DEBUG, "CATrustTest: client $CSI / $user refused fake CA");
    $known{$CSI} = $now-1-$maxTestTime;
  } elsif ($result == $main::ACCEPT || $result == $main::REJECT) {
    #main::log($main::LOG_DEBUG, $result);
    #main::log($main::LOG_DEBUG, $reason);
    &main::log($main::LOG_DEBUG, "CATrustTest: client $CSI / $user leaked his password");

    # record info, that this client already leaked his password
    $leaked{$CSI} = $now;
  };

  if ($result == $main::ACCEPT or $result == $main::REJECT) {
    ${$_[2]} = $main::REJECT;
  };
};

sub tagClient {
  my $p = ${$_[0]};

  my $CSI = $p->get_attr('Calling-Station-Id');
  return unless($CSI);
  my $user = $p->get_attr('User-Name');
  return unless($user);

  my $now = time;

  my $test = 1;
  if (exists $known{$CSI}) {
    # know client, test only if it is recent
    $test = $now <= ($known{$CSI}+$maxTestTime);
  } else {
    # we meet first time
    $known{$CSI} = $now;
  };

  if ($test and (exists $leaked{$CSI})) {
    # client already leaked his password; do not mess his authentication anymore
    $test = 0;
  };

  if ($test) {
    $p->add_attr('CESNET-CATrustTest', 'TEST');
    &main::log($main::LOG_DEBUG, "CATrustTest: testing client $CSI / $user");
    return;
  };

  &main::log($main::LOG_DEBUG, "CATrustTest: not testing client $CSI / $user");
};

sub stopTunnelledRequests {
  my $p = ${$_[0]};
  #my $rp = ${$_[1]};
  #my $result = ${$_[2]};

  if ($p->{tunnelledByPEAP} or
      $p->{tunnelledByTTLS} or
      $p->{tunnelledByFAST}) {

    my $CSI = $p->get_attr('Calling-Station-Id') || '??:??:??:??:??:??';
    my $user = $p->get_attr('User-Name') || 'undef';

    &main::log($main::LOG_DEBUG, "CATrustTest: rejecting tunnelled request for $CSI / $user");

    ${$_[2]} = $main::REJECT;
  };


  return 1;
};


1;

