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
#include <string.h>
#include <gcrypt.h>
#include <libguile.h>

static scm_t_bits md_smob_tag;
static void init_md_smob(void);

SCM_DEFINE (scm_gcrypt_md_open, "gcrypt:md-open", 1, 1, 0,
	    (SCM scm_algo, SCM scm_flags), "")
//SCM gcrypt_md_open (SCM scm_algo, SCM scm_flags)
#define FUNC_NAME "scm_gcrypt_md_open"
{
  SCM smob;
  gcry_md_hd_t  hd; // = NULL;
  int algo = 0;
  int flags = 0;
  gcry_error_t err = 0;

  SCM_ASSERT(scm_integer_p(scm_algo), scm_algo, SCM_ARG1, FUNC_NAME);
  if (! SCM_UNBNDP(scm_flags))
    {
      SCM_ASSERT(scm_integer_p(scm_flags), scm_flags, SCM_ARG2, FUNC_NAME);
      flags = scm_to_int(scm_flags);
    }
  algo = scm_to_int(scm_algo);

  err = gcry_md_test_algo(algo);
  if ( err )
    {
      SCM err_msg;
      err_msg = scm_from_latin1_string ("Invalid digest algorithm: ~A");
      scm_error_scm (scm_misc_error_key, scm_from_latin1_string("gcrypt:quick-hash"),
		     err_msg, scm_list_1(scm_algo), SCM_BOOL_F);
    }

  err = gcry_md_open(&hd, algo, flags);  
  SCM_NEWSMOB (smob, md_smob_tag, hd);

  return smob;  
}
#undef FUNC_NAME

/*
  Reset the context to its initial state. This is the same as md-close
  followed by md-open


  Input hash object
*/
SCM_DEFINE (scm_gcrypt_md_reset, "gcrypt:md-reset", 1, 0, 0,
	    (SCM md_smob), "")
#define FUNC_NAME "scm_gcrypt_md_close"
{
  gcry_md_hd_t hd;
  scm_assert_smob_type (md_smob_tag, md_smob);
  hd = (gcry_md_hd_t) SCM_SMOB_DATA (md_smob);
  gcry_md_reset(hd);

  return SCM_EOL;
}
#undef FUNC_NAME

/*
  Update the digest values.

  Input hash object
  Input bytevector containing the data
  Output true
*/
SCM_DEFINE (scm_gcrypt_md_write, "gcrypt:md-write", 2, 0, 0,
	    (SCM md_smob, SCM bv), "")
#define FUNC_NAME "scm_gcrypt_md_write"
{
  gcry_md_hd_t hd;
  void * buf;
  size_t buflen;

  scm_assert_smob_type (md_smob_tag, md_smob);
  SCM_ASSERT(scm_bytevector_p(bv), bv, SCM_ARG2, FUNC_NAME);

  hd = (gcry_md_hd_t) SCM_SMOB_DATA (md_smob);  
  buf = (void *) SCM_BYTEVECTOR_CONTENTS (bv);
  buflen = SCM_BYTEVECTOR_LENGTH (bv);

  gcry_md_write (hd, buf, buflen);
  
  return SCM_BOOL_T;
}
#undef FUNC_NAME

/*
  NOT WORKING!
  Update the digest value with 1 char

  Input hash object
  Input a char
  Output true
*/
/* SCM_DEFINE (scm_gcrypt_md_putc, "gcrypt:md-putc", 2, 0, 0, */
/* 	    (SCM md_smob, SCM scm_c), "") */
/* #define FUNC_NAME "scm_gcrypt_md_putc" */
/* { */
/*   gcry_md_hd_t hd; */
  
/*   scm_assert_smob_type (md_smob_tag, md_smob); */
/*   SCM_ASSERT(scm_char_p (scm_c), scm_c, SCM_ARG2, FUNC_NAME); */

/*   hd = (gcry_md_hd_t) SCM_SMOB_DATA (md_smob); */

/*   gcry_md_putc (hd, (int) scm_to_char(scm_c)); */

/*   return SCM_BOOL_T; */
/* } */
/* #undef FUNC_NAME */

/*
  Return the result of the message digest calculation. If multiple
  algorithms are enabled use algo to specify which.

  Input hash object
  Input algorithm of choice
  Output '() on fail, else the message digest as bytevector.
*/
SCM_DEFINE (scm_gcrypt_md_read, "gcrypt:md-read", 1, 1, 0,
	    (SCM md_smob, SCM scm_algo), "")
#define FUNC_NAME "scm_gcrypt_md_read"
{
  int algo = 0;
  gcry_md_hd_t hd;
  unsigned char * hash;
  SCM hash_bv;
  unsigned int hashlen;
  
  scm_assert_smob_type (md_smob_tag, md_smob);
  if (! SCM_UNBNDP (scm_algo))
    {
      SCM_ASSERT(scm_integer_p (scm_algo) , scm_algo, SCM_ARG2, FUNC_NAME);
      algo = scm_to_int (scm_algo);
    }

  hd = (gcry_md_hd_t) SCM_SMOB_DATA (md_smob);

  hash = gcry_md_read (hd, algo);
  if (hash == NULL)
    {
      return SCM_EOL;
    }
  // Find out the length of the digest
  if (algo == 0)
    {
      hashlen = gcry_md_get_algo_dlen ( gcry_md_get_algo (hd) );
    }
  else
    {
      hashlen = gcry_md_get_algo_dlen (algo);
    }
  
  hash_bv = scm_c_make_bytevector (hashlen);
  memcpy ((void *) SCM_BYTEVECTOR_CONTENTS (hash_bv), hash, hashlen);

  return hash_bv;  
}
#undef FUNC_NAME

/*
  Close the hash object

  Input hash object
*/
SCM_DEFINE (scm_gcrypt_md_close, "gcrypt:md-close", 1, 0, 0,
	    (SCM md_smob), "")
#define FUNC_NAME "scm_gcrypt_md_close"
{
  gcry_md_hd_t hd;
  scm_assert_smob_type (md_smob_tag, md_smob);

  hd = (gcry_md_hd_t ) SCM_SMOB_DATA (md_smob);

  gcry_md_close(hd);

  return SCM_EOL;
}
#undef FUNC_NAME

/*
  Lookup the name of the algorithm.

  Input algorithm
  Ouput string containing its name or ?
*/
SCM_DEFINE (scm_gcrypt_md_algo_name, "gcrypt:md-algo->name", 1, 0, 0,
	    (SCM scm_algo), "")
#define FUNC_NAME "scm_gcrypt_md_close"
{
  char * string;
  SCM_ASSERT (scm_integer_p (scm_algo), scm_algo, SCM_ARG1, FUNC_NAME);
  string = gcry_md_algo_name (scm_to_int (scm_algo));
  return scm_from_locale_string (string);
  
}

#undef FUNC_NAME

/*
  A method to 'quickly' calculate the hash of a bytevector. No need
  for the md-open; md-update; md-read; md-close sequence.

  Input: bytevector containing the 'message' to encrypt
  Input: algorithm number
  Output: bytevector containing the digest
*/
SCM_DEFINE (scm_gcrypt_quick_hash, "gcrypt:quick-hash", 2, 0, 0,
	    (SCM data_bv, SCM scm_algo), "")
#define FUNC_NAME "gcrypt_quick_hash"
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
      scm_error_scm (scm_misc_error_key, scm_from_latin1_string("gcrypt:quick-hash"),
		     err_msg, scm_list_1(scm_algo), SCM_BOOL_F);
    }
  dlen    = gcry_md_get_algo_dlen (algo);
  
  if ( dlen < 4 ) 
    {
      SCM err_msg;
      err_msg = scm_from_latin1_string ("Invalid digest length: ~A");
      scm_error_scm (scm_misc_error_key, scm_from_latin1_string("gcrpt:quick-hash"),
		     err_msg, scm_list_1(scm_from_int (dlen)), SCM_BOOL_F);
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

static int
print_md_smob (SCM md_smob, SCM port, scm_print_state * pstate)
{
  gcry_md_hd_t hd = (gcry_md_hd_t) SCM_SMOB_DATA (md_smob);

  scm_puts("#<", port);
  // Will return "?" or the name of the algo
  scm_puts(gcry_md_algo_name (gcry_md_get_algo (hd)), port);
  scm_puts(" hash object ", port);
  scm_uintprint(SCM_CELL_WORD_1 (md_smob), 16, port);
  //  scm_uintprint(SCM_UNPACK (exp), 16, port);
  scm_putc ('>', port);
  return 1;
}

static size_t
free_md_smob (SCM md_smob)
{
  gcry_md_hd_t  hd;
  hd = (gcry_md_hd_t ) SCM_SMOB_DATA (md_smob);
  gcry_md_close(hd);
}
  
static void
init_md_smob(void)
{
  md_smob_tag = scm_make_smob_type ("gcrypt-hash-object", sizeof(gcry_md_hd_t));
  scm_set_smob_free ( md_smob_tag, free_md_smob );
  scm_set_smob_print ( md_smob_tag, print_md_smob );
  scm_set_smob_equalp ( md_smob_tag, NULL ); //should always return #f
}

void
scm_gcrypt_hash_init()
{
  /* Version check should be the very first call because it
     makes sure that important subsystems are intialized. */
  if (!gcry_check_version (GCRYPT_VERSION))
    {
      fputs ("libgcrypt version mismatch\n", stderr);
      exit (2);
    }
  init_md_smob();
  #include "hash.x"
}

/*
  gcry_md_enable
  gcry_md_setkey
  gcry_md_copy
  gcry_md_putc
  gcry_md_map_name
  gcry_md_get_asnoid
  gcry_md_test_algo
  gcry_md_get_algo_dlen
  gcry_md_get_algo
  gcry_md_is_secure
  gcry_md_is_enabled
*/
