;;   Copyright (C) 2012 bas smit (fbs)
  
;;   This file is part of Libgcrypt-guile.
  
;;   Libgcrypt is free software; you can redistribute it and/or modify
;;   it under the terms of the GNU Lesser General Public License as
;;   published by the Free Software Foundation; either version 2.1 of
;;   the License, or (at your option) any later version.

;;   Libgcrypt is distributed in the hope that it will be useful,
;;   but WITHOUT ANY WARRANTY; without even the implied warranty of
;;   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;   GNU Lesser General Public License for more details.
  
;;   You should have received a copy of the GNU Lesser General Public
;;   License along with this program; if not, see <http://www.gnu.org/licenses/>.

(define-module (gcrypt hash)
  #:use-module (system foreign)
  #:use-module (rnrs   bytevectors)
  #:export     (
		MD_NONE
		MD_MD5
		MD_SHA1
		MD_RDM160
		MD_MD2
		MD_TIGER
		MD_SHA256
		MD_SHA384
		MD_SHA512
		MD_SHA224
		MD_MD4
		MD_CRC32
		MD_CRC32_RFC1510
		MD_CRC24_RFC2440
		MD_WHIRLPOOL
		MD_TIGER1
		MD_TIGER2
		MD_FLAG_SECURE
		MD_FLAG_HMAC

		algo-digest-length
		hash-bytevector
		algo->name
		name->algo
		;; c functions
		open
		close
		read
		write
		reset
		enable
		))

;; Constants
(define MD_NONE			 0)
(define MD_MD5			 1)
(define MD_SHA1			 2)
(define MD_RMD160		 3) 
(define MD_MD2			 5) 
(define MD_TIGER		 6)  
(define MD_HAVAL		 7)  
(define MD_SHA256		 8)
(define MD_SHA384		 9)
(define MD_SHA512		 10)
(define MD_SHA224		 11)
(define MD_MD4			 301)
(define MD_CRC32		 302)
(define MD_CRC32_RFC1510	 303)
(define MD_CRC24_RFC2440	 304)
(define MD_WHIRLPOOL		 305) 
(define MD_TIGER1		 306) 
(define MD_TIGER2		 307) 

(define MD_FLAG_SECURE 1)
(define MD_FLAG_HMAC   2)

(eval-when (load eval compile)
	   (define libgcrypt (dynamic-link "/data/projects/lib-guile/guilecrypt/src/.libs/libguile-crypt"))
	   (dynamic-call "scm_gcrypt_hash_init" libgcrypt))

(define (algo-digest-length algo)
  (let ([algo_dlen_p
	 (pointer->procedure int
			     (dynamic-func "gcry_md_get_algo_dlen" libgcrypt)
			     (list int))])
    (algo_dlen_p algo)))

(define (hash-bytevector algo bv)
  (let ([algo_hash_buf
	 (pointer->procedure int
			     (dynamic-func "gcry_md_hash_buffer" libgcrypt)
			     (list int '* '* size_t))]
	[digest_len (get-digest-length algo)])
    (if (= 0 digest_len)
	(error "Invalid digest" algo)
	(let ([hash_bv (make-bytevector digest_len)])
	  (begin (algo_hash_buf algo
				(bytevector->pointer hash_bv)
				(bytevector->pointer bv)
				(bytevector-length bv))
		 hash_bv)))))


(define (algo->name algo)
  (let ([algo_name (pointer->procedure '*
				       (dynamic-func "gcry_md_algo_name"
						     libgcrypt)
				       (list int))])
    (pointer->string (algo_name algo))))

(define (name->algo name)
  (let ([name_algo (pointer->procedure int
				       (dynamic-func "gcry_md_map_name"
						     libgcrypt)
				       (list '*))])
    (name_algo (string->pointer name))))

