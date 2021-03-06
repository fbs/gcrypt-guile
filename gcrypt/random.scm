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

(define-module (gcrypt random)
  #:version    (1 0)
  #:use-module (gcrypt internal)
  #:use-module (system foreign)
  #:use-module (rnrs   bytevectors)
  #:export (
	    WEAK_RANDOM
	    STRONG_RANDOM
	    VERY_STRONG_RANDOM

	    randomize
	    create-nonce))

(define WEAK_RANDOM		 0)
(define STRONG_RANDOM		 1)
(define VERY_STRONG_RANDOM	 2)

(define-foreign-procedure
  (gcry_randomize (buffer '*) (length size_t) (level int) -> void)
  #f)

;; Return a bytevector of size `length' filled with random numbers of strength 'level'.
(define MAX_RND_SIZE 1e5)
(define (randomize length level)
  (define (valid-level?)
    (and (integer? level)
	 (<= 0 level 2)))

  (define (valid-length?)
    (and (integer? length)
	 (<= 0 length MAX_RND_SIZE)))
  
  (if (not (valid-length?))
      (error "Invalid length. Expected length to be a postive integer." length)
      (if (not (valid-level?)) 
	  (error "Invalid level." level)
	  (let ([bv (make-bytevector length)])
	    (gcry_randomize (bytevector->pointer bv)
                            length
                            level)
            bv))))

(define-foreign-procedure
  (gcry_create_nonce (buffer '*) (length size_t) -> void)
  #f)

;; Return a bytvector of size 'length' filled with random numbers.
;; This is an extra function
;; nearly independent of the other random function for 3 reasons: It better protects the
;; regular random generator’s internal state, provides better performance and does not
;; drain the precious entropy pool.
(define (create-nonce length)
  (define (valid-length?)
    (and (integer? length)
	 (<= 0 length MAX_RND_SIZE)))

  (if (not (valid-length?))
      (error "Invalid length. Expected length to be a postive integer." length)
      (let ([bv (make-bytevector length)])
	(gcry_create_nonce (bytevector->pointer bv)
                           length)
        bv)))
