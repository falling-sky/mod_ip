# @configure_input @

LDFLAGS = 
LDLIBS = -lresolv 
CFLAGS = -I. -g -O2


mod_ip.la: mod_ip.c ip2asn.c
	apxs2 -n mod_ip -o mod_ip.la -c mod_ip.c ip2asn.c $(CFLAGS) $(LDFLAGS) $(LDLIBS)
	
install:
	apxs2 -n mod_ip -i mod_ip.la
	cat README.configuration

clean:
	rm -fr config.status config.cache config.log  .libs *.o *.la *.lo *.slo configure.scan   autoscan-*.log autom4te.cache config.h work

dist-test:
	make -f Makefile.dist $*

dist-prep:
	make -f Makefile.dist $*
