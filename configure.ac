AC_PREREQ ([2.50])
AC_INIT([gcrypt-guile], 0.2)
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([modules/hash.scm])
AM_SILENT_RULES([yes])		

AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE()

#LT_INIT()

#AC_LANG([C])
#AC_PROG_CC()
#AM_PROG_CC_C_O()

GUILE_PROGS()
GUILE_SITE_DIR()

if $GUILE_TOOLS | grep -q compile; then
   # everything cool
   true
else
   AC_MSG_ERROR([Guile 2.0 required.])
fi

AM_PATH_LIBGCRYPT(1)
PKG_CHECK_MODULES([GUILE], [guile-2.0])

AC_CONFIG_FILES([Makefile] [modules/Makefile])

AC_OUTPUT()
