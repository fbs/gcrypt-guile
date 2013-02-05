GUILE_FLAGS = -Wunbound-variable -Warity-mismatch -Wformat

SOURCES = \
	gcrypt/hash.scm \
	gcrypt/internal.scm \
	gcrypt/random.scm

GOBJECTS = $(SOURCES:%.scm=%.go)

scmdir = $(GUILE_SITE)
godir = $(libdir)/guile/2.0/ccache

nobase_scm_DATA = $(SOURCES)
nobase_go_DATA = $(GOBJECTS) 

guile_install_go_files = install-nobase_goDATA
$(guile_install_go_files): install-nobase_scmDATA

SUFFIXES = .scm .go
CLEANFILES = $(GOBJECTS)
EXTRA_DIST = $(SOURCES)

.scm.go:
	$(GUILE_TOOLS) compile $(GUILE_FLAGS) -o "$@" "$<"

EXTRA_DIST += env.in
