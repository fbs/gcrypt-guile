;;   Copyright (C) 2013 Daniel Hartwig <mandyke@gmail.com>
  
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

(define-module (gcrypt internal)
  #:version (1 0)
  #:use-module (system foreign)
  #:export (define-foreign-procedure))

(define libgcrypt (dynamic-link "libgcrypt"))

(define-syntax foreign-procedure
  (lambda (x)
    (syntax-case x (->)
      ((_ (name (pname ptype) ... -> type))
       (with-syntax ((sname (symbol->string (syntax->datum #'name))))
         #'(pointer->procedure type
                               (dynamic-func sname libgcrypt)
                               (list ptype ...)))))))

(define-syntax define-foreign-procedure
  (syntax-rules (->)
    ((_ (name (pname ptype) ... -> type)
        docstring)
     (define name
       (letrec ((proc (foreign-procedure
                       (name (pname ptype) ... -> type)))
                (name (lambda (pname ...)
                        docstring
                        (proc pname ...))))
         name)))))
