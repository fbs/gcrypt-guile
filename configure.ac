AC_PREREQ ([2.50])
AC_INIT([gcrypt-guile], 0.2)
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([src/hash.scm])
AM_SILENT_RULES([yes])		

AM_INIT_AUTOMAKE()

LT_INIT()

AC_LANG([C])
AC_PROG_CC()
AM_PROG_CC_C_O()

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

if test "x$GCC" = "xyes"; then
# Enable useful GCC compilation flags.
  GCC_CFLAGS="-Wall -Werror -Wcast-align -Wpointer-arith -Wformat \
		  -Wformat-security -std=c99"
else
  GCC_CFLAGS=""
fi
AC_SUBST([GCC_CFLAGS])

AC_ARG_ENABLE([debug],
	      AS_HELP_STRING([--enable-debug], [enable debugging for c files]),
	      [debug=true],
	      [debug=false])
AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])

AC_ARG_ENABLE([cmodules],
	      AS_HELP_STRING([--enable-cmodules], [enable cmodulesging for c files]),
	      [cmodules=true],
	      [cmodules=false])
AM_CONDITIONAL([CMODULES], [test x$cmodules = xtrue])

if test "$debug" = "true"; then
    AC_MSG_NOTICE([NOTICE: debug enabled])
fi

if test "$cmodules" = "true"; then
    AC_MSG_NOTICE([NOTICE: cmodules enabled])
fi			   


AC_CONFIG_FILES([Makefile] [src/Makefile])

AC_OUTPUT()
