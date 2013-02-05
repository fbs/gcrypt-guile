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
  #:version    (1 0)
  #:use-module (gcrypt internal)
  #:use-module (system foreign)
  #:use-module (rnrs   bytevectors)
  #:export     (MD_NONE
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

		hash?
		make-hash
		change-digest-algorithm
		update!
		digest
		digest->hex-string
		reset-buffer!
		quick-hash
		blocksize
		algorithm->name))

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

;; scheme api
(define* (make-hash #:optional (algorithm MD_SHA256))
  "Create a new hash-object using @var{algorithm} as hash algorithm"
  (if (not (valid-algorithm? algorithm))
      (error "make-hash: invalid algorithm" algorithm)
      (make-hash-type algorithm (make-bytevector 0))))

(define (update! hash data)
  "Update the buffer of hash-object @var{hash} with string or bytevector @var{data}.
The return value is @var{data}."
  (let ([msg (cond [(string? data) (string->utf8 data)]
		   [(bytevector? data) data]
		   [else (error "write-hash: expected string or bytevector, got" data)])])
    (set-buffer! hash (bytevector-concat (buffer hash) msg))
    data))

(define (change-digest-algorithm hash algorithm)
  "Use @var{algo} as digest algorithm, @var{algo} must be a valid algorithm."
  (if (valid-algorithm? algorithm)
      (set-algorithm! hash algorithm)
      (error "change-digest-algorithm: invalid algorithm" algorithm)))

(define (digest hash)
  "Calculate the digest (of data passed using write-hash).
The return value is the digest as bytevector."
  (hash-bytevector (algorithm hash) (buffer hash)))

(define (digest->hex-string digest)
  "Convert message digest @var{digest} to a hex-string.
 #vu8(1 11 16) -> \"1b10\"" 
  (string-concatenate (map (lambda (x) (number->string x 16)) 
			   (bytevector->u8-list digest))))

(define (reset-buffer! hash)
  "Reset the buffer of hash-object @var{hash}."
  (set-buffer! hash (make-bytevector 0)))

(define (quick-hash algorithm data)
  "Calculate the digest of a string or bytevector @var{data}."
  (let ([dd (cond [(string? data) (string->utf8 data)]
		  [(bytevector? data) data]
		  [else (error "quick-hash: expected string or bytevector, got" data)])])
    (if (valid-algorithm? algorithm)
	(hash-bytevector algorithm dd)
	(error "quick-hash: invalid algorithm " algorithm))))

(define (digest-size obj)
  "Return the digest size of the hash algorithm @var{obj}. @var{obj} must be either an
hash-object or a hash function name (MD_*)."
  (cond [(hash? obj) (algo->dlen (algorithm obj))]
	[(valid-algorithm? obj) (algo->dlen obj)]
	[else (error "blocksize: expected hash-object or hash-name, got" obj)]))

(define (hash? obj)
  "Return #t if @var{obj} is an hash-object, #f otherwise."
  (record-predicate hash-type))

(define (algorithm->name obj)
  "Lookup the name of the used algorithm."
  (if (not (valid-algorithm? obj))
      (error "algorithm->name: invalid algorithm" algorithm)
      (algo->name obj)))

;; internal data type
(define hash-type (make-record-type "HASH"
				    '(algorithm
				      buffer)
				    (lambda (hash port)
				      (format port 
					      "#<~A HASH>" 
					      (algo->name (algorithm hash))))))

(define make-hash-type (record-constructor hash-type))
(define buffer (record-accessor hash-type 'buffer))
(define algorithm (record-accessor hash-type 'algorithm))
(define set-buffer! (record-modifier hash-type 'buffer))
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
(define-foreign-procedure
  (gcry_md_get_algo_dlen (algo int) -> unsigned-int)
  #f)

(define (algo->dlen algo)
  (gcry_md_get_algo_dlen algo))

(define-foreign-procedure
  (gcry_md_hash_buffer (algo int)
                       (digest '*)
                       (buffer '*)
                       (length size_t)
                       ->
                       void)
  #f)

(define (hash-bytevector algo bv)
  (let ([digest_len (algo->dlen algo)])
    (if (= 0 digest_len)
	(error "Invalid digest" algo)
	(let ([digest (make-bytevector digest_len)])
	  (gcry_md_hash_buffer algo
                               (bytevector->pointer digest)
                               (bytevector->pointer bv)
                               (bytevector-length bv))
          digest))))

(define-foreign-procedure
  (gcry_md_algo_name (algo int) -> '*)
  #f)

(define (algo->name algo)
  (pointer->string (gcry_md_algo_name algo)))

(define-foreign-procedure
  (gcry_md_map_name (name '*) -> int)
  #f)

(define (name->algo name)
  (gcry_md_map_name (string->pointer name)))
