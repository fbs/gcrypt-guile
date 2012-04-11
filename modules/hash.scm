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
	    ))

(dynamic-call "gcrypt_hash_init" (dynamic-link "libguile-crypt"))

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

