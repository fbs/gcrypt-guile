AC_PREREQ([2.50])
AC_INIT([guilecrypt], 0.1)

AM_INIT_AUTOMAKE([-Wall])
LT_INIT

AC_CONFIG_FILES([Makefile] [src/Makefile])

AC_CONFIG_SRCDIR([src/hash.c])

AC_LANG([C])
AC_PROG_CC
AM_PROG_CC_C_O

if test "x$GCC" = "xyes"; then
  # Enable useful GCC compilation flags.
  GCC_CFLAGS="-Wall -Werror -Wcast-align -Wpointer-arith"
else
  GCC_CFLAGS=""
fi
AC_SUBST([GCC_CFLAGS])

AM_PATH_LIBGCRYPT(1)
PKG_CHECK_MODULES([GUILE], [guile-2.0])

AC_OUTPUT
