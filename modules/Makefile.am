GUILE_FLAGS = -Wunbound-variable -Warity-mismatch -Wformat

SCM_SOURCES = 		\
	hash.scm 	\
	random.scm    	\
	prime.scm

GOBJECTS		 = $(SCM_SOURCES:%.scm=%.go)

scmdir			 = $(GUILE_SITE)/gcrypt/
godir			 = $(libdir)/guile/2.0/ccache/gcrypt

nobase_scm_DATA		 = $(SCM_SOURCES)
nobase_go_DATA		 = $(GOBJECTS) 

guile_install_go_files	 = install-nobase_goDATA
$(guile_install_go_files): install-nobase_scmDATA

SUFFIXES		 = .scm .go
CLEANFILES		 = $(GOBJECTS)

.scm.go:
	$(GUILE_TOOLS) compile $(GUILE_FLAGS) -o "$@" "$<"
