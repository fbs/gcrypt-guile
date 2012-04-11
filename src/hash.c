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
scm_gcrypt_quick_hash(SCM scm_str, SCM scm_algo)
#define FUNC_NAME "gcrypt:quick-hash"
{
  SCM_ASSERT(scm_string_p(scm_str), scm_str, SCM_ARG1, FUNC_NAME);
  SCM_ASSERT(scm_integer_p(scm_algo), scm_algo, SCM_ARG2, FUNC_NAME);

  int		algo	= scm_to_int(scm_algo);
  char *	str	= scm_to_locale_string(scm_str);
  int		dig_len = gcry_md_get_algo_dlen(algo);
  SCM		bv	= scm_c_make_bytevector (dig_len);
  char *	digest	= (char *) SCM_BYTEVECTOR_CONTENTS(bv);
  
  gcry_error_t  err	= 0;
  
  err = gcry_md_test_algo(algo);  
  if ( err )
    {
      SCM		err_msg;
      err_msg = scm_from_latin1_string ("Invalid digest algorithm: ~A");
      scm_error_scm (scm_misc_error_key, scm_from_latin1_string("gcrypt:quick-hash"),
		     err_msg, scm_list_1(scm_algo), SCM_BOOL_F);
    }
  
  gcry_md_hash_buffer (algo, digest, str, strlen(str));

  return bv;
}

#undef FUNC_NAME

void gcrypt_hash_init()
{
  scm_c_define_gsubr ("gcrypt:quick-hash", 2, 0, 0, scm_gcrypt_quick_hash);
}
 


