AM_CFLAGS = $(GCC_FLAGS)
AM_LDFLAGS = $(LIBGCRYPT_LIBS) $(GUILE_LIBS)

if DEBUG
AM_CFLAGS += -g
endif

SCM_SOURCES = 		\
	hash.scm 	\
	random.scm

GOBJECTS = $(SCM_SOURCES:%.scm=%.go)

scmdir = $(GUILE_SITE)/gcrypt/
scm_DATA = $(GOBJECTS) $(SCM_SOURCES)

SUFFIXES = .x .scm
CLEANFILES =
BUILT_SOURCES = 

if CMODULES
lib_LTLIBRARIES = libgcrypt-guile.la
libgcrypt_guile_la_CFLAGS = $(AM_CFLAGS) $(GUILE_CFLAGS) $(LIBGCRYPT_CLAGS)
libgcrypt_guile_la_LIBADD = $(LIBGCRYPT_LIBS) $(GUILE_LTLIBS)
libgcrypt_guile_la_SOURCES = hash.c

SNARF_FILES = $(libgcrypt_guile_la_SOURCES:.c=.x)
CLEANFILES += $(SNARF_FILES)
BUILT_SOURCES += $(SNARF_FILES)
endif

.c.x:
	guile-snarf $(libgcrypt_guile_la_CFLAGS) "$<" > "$@" || { rm "$@"; false; }

.scm.go:
	guild compile -o "$@" "$<"
