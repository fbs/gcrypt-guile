GUILE_FLAGS = -Wunbound-variable -Warity-mismatch -Wformat

moddir = $(prefix)/share/guile/site/2.0
godir=$(libdir)/guile/2.0/site-ccache

SOURCES = \
	gcrypt/internal.scm \
	gcrypt/hash.scm \
	gcrypt/random.scm


GOBJECTS = $(SOURCES:%.scm=%.go)

nobase_mod_DATA = $(SOURCES) $(NOCOMP_SOURCES)
nobase_go_DATA = $(GOBJECTS)

guile_install_go_files = install-nobase_goDATA
$(guile_install_go_files): install-nobase_modDATA

CLEANFILES = $(GOBJECTS)
EXTRA_DIST = $(SOURCES) $(NOCOMP_SOURCES)
GUILE_WARNINGS = -Wunbound-variable -Warity-mismatch -Wformat
SUFFIXES = .scm .go

.scm.go:
	$(AM_V_GEN)$(top_builddir)/env $(GUILE_TOOLS) compile $(GUILE_WARNINGS) -o "$@" "$<"


