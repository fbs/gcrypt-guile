AC_PREREQ([2.50])
AC_INIT([guilecrypt], 0.1)
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([src/hash.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall])

LT_INIT()

AC_LANG([C])
AC_PROG_CC
AM_PROG_CC_C_O

if test "x$GCC" = "xyes"; then
  # Enable useful GCC compilation flags.
  GCC_CFLAGS="-Wall -Werror -Wcast-align -Wpointer-arith -Wformat -Wformat-security"
  CSTD="-std=gnu99"
else
  GCC_CFLAGS=""
fi

AC_SUBST([GCC_CFLAGS])
AC_SUBST([CSTD])

GUILE_PROGS
GUILE_SITE_DIR

AM_PATH_LIBGCRYPT(1)
PKG_CHECK_MODULES([GUILE], [guile-2.0])

AC_CONFIG_FILES([Makefile] [src/Makefile] [modules/Makefile])
AC_OUTPUT
