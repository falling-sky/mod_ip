#! /usr/bin/perl

# Scan the SIXXS pops page,
# Screen scrape it to generate the CHECK_PREFIX lines in mod_ip.c

 # Output will be like
#   CHECK_PREFIX("2001:14b8:100::/40","fihel01.sixxs.net dna");
#   CHECK_PREFIX("2001:15c0:65ff::/48","simbx01.sixxs.net amis");
#   CHECK_PREFIX("2001:15c0:6600::/40","simbx01.sixxs.net amis");
               

use strict;
use LWP::Simple qw(get);

my $top_url  = "http://www.sixxs.net/pops/prefixes/";
my $top_html = get($top_url);
my @lines    = split( /\n/, $top_html );
@lines = grep( m#/tools/whois#, @lines );
foreach my $line (@lines) {
    if ( $line =~ m#href="/tools/whois/\?(\S+?)">\1# ) {
        my ($ip) = $1;
        if ( $line =~
            m#<td>(?:Subnets|Tunnels)</td><td><a href="\.\./(.*?)/">(\S+)</a></td><td><a href=".*?">(.*?)</a></td></tr>$#
           )
        {
            print <<"EOF";
\t\tmod_ip_prefix $ip "$2\.sixxs.net $1"
EOF
        }
    }
}

