AM_CFLAGS = -Wall -Werror -Wcast-align -Wpointer-arith -Wformat -Wformat-security
AM_CFLAGS += -std=gnu99

AM_LDFLAGS = $(LIBGCRYPT_LIBS) $(GUILE_LIBS)

lib_LTLIBRARIES = libgcrypt-guile.la

libgcrypt_guile_la_CFLAGS = $(AM_CFLAGS) $(GUILE_CFLAGS) $(LIBGCRYPT_CLAGS)
libgcrypt_guile_la_LIBADD = $(LIBGCRYPT_LIBS) $(GUILE_LTLIBS)

libgcrypt_guile_la_SOURCES = hash.c

SNARF_FILES = $(libgcrypt_guile_la_SOURCES:.c=.x)
CLEANFILES = $(SNARF_FILES)
BUILT_SOURCES = $(SNARF_FILES)
SUFFIXES = .x

.c.x:
	guile-snarf $(libgcrypt_guile_la_CFLAGS) "$<" > "$@" || { rm "$@"; false; }
