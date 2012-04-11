AM_CFLAGS  = $(GCC_FLAGS) -std=gnu99 -Wformat -Wformat-security
AM_LDFLAGS = $(LIBGCRYPT_LIBS) $(GUILE_LIBS)

lib_LTLIBRARIES = libguile-crypt.la
libguile_crypt_la_SOURCES = \
	hash.c

libguile_crypt_la_CFLAGS = $(LIBGCRYPT_CFLAGS) $(GUILE_CFLAGS) $(AM_CFLAGS)
libguile_crypt_la_LIBADD = $(LIBGCRYPT_LIBS) $(GUILE_LIBS)
