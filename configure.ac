AC_PREREQ([2.68])
AC_INIT([Falling Sky mod_ip], [1.0], [http://code.google.com/p/falling-sky/issues/list], [mod_ip], [http://code.google.com/p/falling-sky])
AC_HEADER_RESOLV
AC_CHECK_HEADERS([arpa/inet.h arpa/nameser.h netinet/in.h stdlib.h string.h sys/socket.h])
AC_CHECK_FUNCS([memset strchr])
AC_SEARCH_LIBS([res_querydomain],[resolv])
AC_SEARCH_LIBS([__res_querydomain],[resolv])

# Find a suitable apxs
AC_ARG_WITH(apxs,
    [  --with-apxs=PATH        path to Apache apxs],
    [
        if test "$withval" = "yes"; then
            AC_CHECK_PROGS(APXS, apxs2 apxs /opt/local/apache2/bin/apxs /usr/local/bin/apxs, reject)
        else
            APXS=$withval
            AC_SUBST(APXS)
        fi
    ],
    [
        AC_CHECK_PROGS(APXS, apxs2 apxs /opt/local/apache2/bin/apxs /usr/local/bin/apachectl, reject)
    ])
if test "$APXS" = "reject"; then
  AC_MSG_ERROR([Could not find apxs on the path.])
fi


AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

