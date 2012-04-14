  ;; Copyright (c) 2012, bas smit (fbs) . All rights reserved.
 
  ;; This library is free software; you can redistribute it and/or
  ;; modify it under the terms of the GNU Lesser General Public
  ;; License as published by the Free Software Foundation; either
  ;; version 3 of the License, or (at your option) any later version.
 
  ;; This library is distributed in the hope that it will be useful,
  ;; but WITHOUT ANY WARRANTY; without even the implied warranty of
  ;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  ;; Lesser General Public License for more details.
 
  ;; You should have received a copy of the GNU Lesser General Public
  ;; License along with this library; if not,  If not, see <http://www.gnu.org/licenses/>.
 
(define-module (guilecrypt hash)
  #:export (
	    ;; different md algorithms
	    MD_NONE		
	    MD_MD5			
	    MD_SHA1		
	    MD_RMD160		
	    MD_MD2	
	    MD_TIGER
	    MD_HAVAL
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

	    gcrypt:md-open
	    gcrypt:md-reset
	    gcrypt:md-write
	    gcrypt:md-read
	    gcrypt:md-close
	    gcrypt:md-algo->name
	    gcrypt:quick-hash
	    ))

(eval-when (load eval compile)
  (load-extension "libguile-crypt" "scm_gcrypt_hash_init"))

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

