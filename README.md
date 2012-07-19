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
	(use-modules 
		(gcrypt hash)
		(gcrypt random)
		(rnrs bytevectors))

	(randomize 10 WEAK_RANDOM)
	(define hash (make-hash MD_MD5))
	(update! hash "hello world")
	(digest->hex-string (digest hash)) 
		=> "5eb63bbbe01eeed093cb22bb8f5acdc3"
	(change-digest-algorithm hash MD_SHA1)
	(digest->hex-string (digest hash))
		=> "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
	 
Dependencies
------------
Guile (>2.0), Guile-tools & libgcrypt.

