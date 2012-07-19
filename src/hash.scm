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

		make-hash
		write-hash
		read-hash
		reset-hash
		algo->name
		name->algo
		algo->dlen
		
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

(eval-when (load eval compile)
	   (define libgcrypt (dynamic-link "libgcrypt")))

;; scheme api
(define* (make-hash #:key (algorithm MD_SHA256) (message (make-bytevector 0)))
  (if (not (bytevector? message))
      (error "Expected bytevector" message)
      (if (not (valid-algorithm? algorithm))
	  (error "Invalid algorithm" algorithm)
	  (make-hash-type algorithm message))))

(define (write-hash hash msg)
  (if (not (bytevector? msg))
      (error "Expected bytevector" msg)
      (if (not (hash? hash))
	  (error "Expected hash-type" hash)
	  (begin (set-message! hash (bytevector-concat (message hash)
						       msg))
		 msg))))

(define* (read-hash hash #:optional algo)
  (if (not (hash? hash))
      (error "Expected hash-type" hash)
      (hash-bytevector (algorithm hash) (message hash))))

(define (reset-hash hash)
  (if (not (hash? hash))
      (error "Expected hash-type" hash)
      (set-message! hash (make-bytevector 0))))

;; internal data type
(define (print-hash-type hash port)
  (format port "#<~A HASH>" (algo->name (algorithm hash))) port)

(define hash-type (make-record-type "HASH"
				    '(algorithm
				      message)
				    print-hash-type))

(define make-hash-type (record-constructor hash-type))
(define hash? (record-predicate hash-type))
(define message (record-accessor hash-type 'message))
(define algorithm (record-accessor hash-type 'algorithm))
(define set-message! (record-modifier hash-type 'message))
(define set-algorithm! (record-modifier hash-type 'algorithm))

;; internal functions

;; Combine two bytevectors in a newly allocated bytevector. 
(define (bytevector-concat bv1 bv2)
  (if (not (and (bytevector? bv1) (bytevector? bv2)))
      (error "Expected bytevectors" bv1 bv2)
      (let* ([lenbv1 (bytevector-length bv1)]
	     [lenbv2 (bytevector-length bv2)]
	     [dest (make-bytevector (+ lenbv1 lenbv2))])
	(begin
	  (bytevector-copy! bv1 0 dest 0 lenbv1)
	  (bytevector-copy! bv2 0 dest lenbv1 lenbv2)
	  dest))))

(define (valid-algorithm? algorithm)
  (and (number? algorithm)
       (exact? algorithm)
       (< 0 (algo->dlen algorithm))))

;; C api wrappers
(define (algo->dlen algo)
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
	[digest_len (algo->dlen algo)])
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

