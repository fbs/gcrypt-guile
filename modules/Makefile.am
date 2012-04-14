SOURCES = \
	hash.scm

GOBJECTS = $(SOURCES:%.scm=%.go)

scmdir = $(GUILE_SITE)/guilecrypt/
scm_DATA = $(SOURCES)

#godir = $(scmdir)
#go_DATA = $(GOBJECTS)

CLEANFILES = $(GOBJECTS) $(scm_DATA)
EXTRA_DIST = $(scm_DATA)

.scm.go:
	guild compile -o "$@" "$<"
