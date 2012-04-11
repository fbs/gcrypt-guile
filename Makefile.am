AM_CPPFLAGS = $(LIBGCRYPT_CFLAGS) $(GUILE_CFLAGS)
LDADD = $(LIBGCRYPT_LIBS) $(GUILE_LIBS)

noinst_PROGRAMS = guilecrypt
guilecrypt_SOURCES =			\
			src/hash.c

guilecrypt_CFLAGS = -Wall -Werror -Wformat -Wformat-security -fPIC -shared -std=gnu99
#guilecrypt_LDFLAGS =


