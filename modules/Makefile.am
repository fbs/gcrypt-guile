SCM_SOURCES = 		\
	hash.scm 	\
	random.scm    	\
	prime.scm

GOBJECTS = $(SCM_SOURCES:%.scm=%.go)

scmdir = $(GUILE_SITE)/gcrypt/
scm_DATA = $(GOBJECTS) $(SCM_SOURCES)

SUFFIXES = .x .scm
CLEANFILES =
BUILT_SOURCES = 

.scm.go:
	guild compile -o "$@" "$<"
