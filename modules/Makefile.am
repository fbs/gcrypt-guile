SOURCES = \
	hash.scm
	key.scm
	prime.scm
	random.scm

GOBJECTS = $(SOURCES:%.scm=%.go)

scmdir = $(GUILE_SITE)/gcrypt/
scm_DATA = $(SOURCES) $(GOBJECTS)

CLEANFILE = $(scm_DATA) $(GOBJECTS) $(scmdir)
EXTRA_DIST = $(scm_DATA) $(GOBJECTS)

.scm.go:
	guild compile -o "$@" "$<"
