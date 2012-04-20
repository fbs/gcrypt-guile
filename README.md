Guile-crypt
===========
Wrappers to get some libgcrypt functionality into guile.

Disclaimer
----------
I wrote this because I needed some crypto stuff for [crypto-class](www.crypto-class.org).
I am not a cryptography expert so don't expect this `library' to be secure.

Installing
----------
Git-clone the repo and build.

	 $ git clone git@github.com:fbs/gcrypt-guile.git
	 $ cd gcrypt-guile
	 $ ./autogen.sh ; ./configure ; make ; sudo make install

Usage
-----

Note that this could change over time. 

	(use-modules (gcrypt hash)
		     (gcrypt random)
		     (rnrs bytevectors))

	(randomize 10 WEAK_RANDOM)
	(define sha256 (make-hash #:algorithm MD_SHA256))
	sha256 => #<SHA256 HASH>
	(write-hash sha256 (string->utf8 "hello world"))
	(read-hash sha256) => #vu8(185 77 39 185 147 ... 239 205 233)
	(reset-hash sha256)
	 
Dependencies
------------
Guile (>2.0), Guile-tools & libgcrypt.

