
# mod_ip

Apache module to report IP address to web clients as a JSON response

## Description

This module reports the IP the user came from, as a JSONP response.
GET requests required; CGI style arguments are permitted.

| argument           | description                                             |
|--------------------|---------------------------------------------------------|
| `callback=[name]`  | to call a function name of your choosing                |
| `size=[number]`    | to pad the http data portion of the response.  (Does not attempt to offset header response) |
| `asn=1`            | peform ISP ASN and name lookups                         |
| `testip=IPADDRESS` | to override the IP address, force it to look up another |

If the callback is "?", it will output to the screen (calling it "callback"),
using plain text.  Any other name, will output a JSON script instead,
using the callback name specified.

Example:

`http://test-ipv6.com/ip/?callback=hello&testip=2001:470:1:18::2&asn=1`

Returns:

`hello({"ip":"2001:470:1:18::2","type":"ipv6","subtype":"","via":"","asn":"6939","asn_name":"HURRICANE - Hurricane Electric, Inc.","asnlist":"6939","padding":""})`

# Installation

```Bash
./configure
make
sudo make install   
```

# Activation 

Something like this should be in your web server config; it should have been
placed there automaticaelly with "make install".  The apache build system
would have taken care of that for you.

```ApacheConfig
LoadModule mod_ip_module      libexec/apache22/mod_ip.so
```

The above step MAY be done for you, if you run "make activate".  
This feature is OS dependent.  It is known that for Ubuntu you'll need
to do this by hand.

# Configuration

Even on platforms were activation was automatic, configuration was not.
You'll need to explicitly enable mod_ip for the paths you want it in.
For the falling-sky project, we outline it below:

```ApacheConfig

    <VirtualHost test-ipv6.com>
    ..

    # mod_ip - reports IP address.  CGI arguements: callback= and fill=
    # This is a custom module in the test-ipv6.com archive.
    # This was implemented as a module for performance reasons.
    # /ip/ is *the* single most requested element (9 or more times per client!)
    <LocationMatch ^/ip/?$>
     SetHandler mod_ip
    </locationMatch>

    # You may optionally include the output of ./scan-sixxs.pl here

    </VirtualHost>
````


