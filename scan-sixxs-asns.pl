#! /usr/bin/perl

# Scan the SIXXS pops page,
# Screen scrape it to generate the CHECK_PREFIX lines in mod_ip.c

# Output will be like
#   CHECK_PREFIX("2001:14b8:100::/40","fihel01.sixxs.net dna");
#   CHECK_PREFIX("2001:15c0:65ff::/48","simbx01.sixxs.net amis");
#   CHECK_PREFIX("2001:15c0:6600::/40","simbx01.sixxs.net amis");

use strict;
use LWP::Simple qw(get);
use Socket;
use Socket6;

my $top_url  = "http://www.sixxs.net/pops/prefixes/";
my $top_html = get($top_url);
my @lines    = split( /\n/, $top_html );
@lines = grep( m#/tools/whois#, @lines );
foreach my $line (@lines) {
    if ( $line =~ m#href="/tools/whois/\?(\S+?)">\1# ) {
        my ($ip) = $1;
        my ( $prefix, $bits ) = split( m#/#, $ip );
        my $buffer = inet_pton( AF_INET6,$prefix );
        if ( length($buffer) ) {
            my $ipnew = unpack( "H*", $buffer );
            my @ipnew = split(//,$ipnew);
            my $lookup = join(".",reverse(@ipnew),"origin6.asn.cymru.com.");
            my $cmd = "dig +short +notcp $lookup TXT";
            system $cmd;
        }
        next;
        
        my $url = "http://test-ipv6.com/ip/?testip=$prefix&asn=1";
        print STDERR "..";
        my $got = get($url);
        print STDERR "..\n";
        if ( $got =~ m#,"asn":"(\d+)",# ) {
            print "$prefix $1\n";
        } else {
            print $got;
        }
    }
} ## end foreach my $line (@lines)

