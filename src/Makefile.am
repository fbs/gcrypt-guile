AM_CFLAGS  = $(GCC_FLAGS) $(CSTD)
AM_LDFLAGS = $(LIBGCRYPT_LIBS) $(GUILE_LIBS)



#extensiondir = $(GUILE_EXTENSION_DIR)
lib_LTLIBRARIES = libguile-crypt.la

libguile_crypt_la_SOURCES = \
	hash.c

libguile_crypt_la_CFLAGS  = $(LIBGCRYPT_CFLAGS) $(GUILE_CFLAGS) $(AM_CFLAGS)
libguile_crypt_la_LIBADD  = $(LIBGCRYPT_LIBS)   $(GUILE_LTLIBS)

DOT_X_FILES = $(libguile_crypt_la_SOURCES:.c=.x)
CLEANFILES = $(DOT_X_FILES)
BUILT_SOURCES = $(DOT_X_FILES)
SUFFIXES = .x 

.c.x:
	guile-snarf $(libguile_crypt_la_CFLAGS)  "$<" > "$@" || { rm "$@"; false; }
