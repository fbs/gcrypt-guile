/*
 * Copyright (c) 2012, bas smit (fbs) . All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not,  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>

#include <gcrypt.h>
#include <libguile.h>

SCM
scm_gcrypt_quick_hash(SCM data_bv, SCM scm_algo)
#define FUNC_NAME "gcrypt_quick-hash"
{
  SCM_ASSERT(scm_bytevector_p(data_bv), data_bv, SCM_ARG1, FUNC_NAME);
  SCM_ASSERT(scm_integer_p(scm_algo), scm_algo, SCM_ARG2, FUNC_NAME);

  int		algo	= scm_to_int(scm_algo);
  unsigned int  dlen    ;
  SCM		hash_bv	;
  gcry_error_t  err	= 0;
  
  err = gcry_md_test_algo(algo);
  
  if ( err )
    {
      SCM err_msg;
      err_msg = scm_from_latin1_string ("Invalid digest algorithm: ~A");
      scm_error_scm (scm_misc_error_key,
		     scm_from_latin1_string("gcrypt:quick-hash"),
		     err_msg,
		     scm_list_1(scm_algo),
		     SCM_BOOL_F);
    }

  dlen    = gcry_md_get_algo_dlen (algo);
  
  if ( dlen < 4 ) 
    {
      SCM err_msg;
      err_msg = scm_from_latin1_string ("Invalid digest length: ~A");
      scm_error_scm (scm_misc_error_key,
		     scm_from_latin1_string("gcrpt:quick-hash"),
		     err_msg,
		     scm_list_1(scm_from_int (dlen)),
		     SCM_BOOL_F);
    }
  
  hash_bv = scm_c_make_bytevector (dlen);
  //gcry_md_hash (algo, digest, buffer, length)
  gcry_md_hash_buffer (algo,
		       (void *) SCM_BYTEVECTOR_CONTENTS(hash_bv),
		       (void *) SCM_BYTEVECTOR_CONTENTS(data_bv),
		       SCM_BYTEVECTOR_LENGTH(data_bv));

  return hash_bv;
}

#undef FUNC_NAME

void gcrypt_hash_init()
{
  /* Version check should be the very first call because it
makes sure that important subsystems are intialized. */
  if (!gcry_check_version (GCRYPT_VERSION))
    {
      fputs ("libgcrypt version mismatch\n", stderr);
      exit (2);
    }
  
  scm_c_define_gsubr ("gcrypt:quick-hash", 2, 0, 0, scm_gcrypt_quick_hash);
}
 


