/*
  Copyright (C) 2012 bas smit (fbs)
  
  This file is part of Libgcrypt-guile.
  
  Libgcrypt is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of
  the License, or (at your option) any later version.

  Libgcrypt is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <string.h>

#include <gcrypt.h>
#include <libguile.h>

#define GCRYPT_NO_DEPRECATED

#define HASHOBJ_OPEN_P(X) ((X)->bufsize < 0)
#define HASHOBJ_CLOSE(X) ((X)->bufsize = -1)

static scm_t_bits gcry_md_hd_t_tag;
static void init_smob(void);


SCM_DEFINE (scm_gcry_md_open, "open", 1, 1, 0,
	    (SCM algo, SCM flags), "")
#define FUNC_NAME "scm_gcry_md_open"
{
  SCM smob;
  gcry_md_hd_t hd;
  int _algo = 0;
  int _flags = 0;
  gcry_error_t err = 0;

  SCM_ASSERT (scm_integer_p(algo), algo, SCM_ARG1, FUNC_NAME);
  if (!SCM_UNBNDP(flags))
    {
      SCM_ASSERT (scm_integer_p (flags), flags, SCM_ARG2, FUNC_NAME);
      _flags = scm_to_int (flags);
    }
  _algo = scm_to_int (algo);

  err = gcry_md_test_algo (_algo);
  if ( err )
    {
      SCM err_msg = scm_from_locale_string ( gcry_strerror (err) );
      scm_error_scm (scm_misc_error_key, scm_from_locale_string ("open"),
		     err_msg, SCM_BOOL_F, SCM_BOOL_F);
    }
  err = gcry_md_open(&hd, _algo, _flags);
  SCM_NEWSMOB (smob, gcry_md_hd_t_tag, hd);

  return smob;    
}
#undef FUNC_NAME

SCM_DEFINE (scm_gcry_md_enable, "enable", 2, 0, 0,
	    (SCM hobj, SCM algo), "")
#define FUNC_NAME "scm_gcry_enable"
{
  gcry_md_hd_t hd;
  gcry_error_t err = 0;
  scm_assert_smob_type (gcry_md_hd_t_tag, hobj);
  SCM_ASSERT (scm_integer_p (algo), algo, SCM_ARG2, FUNC_NAME);
  hd = (gcry_md_hd_t) SCM_SMOB_DATA (hobj);

  err = gcry_md_test_algo (scm_to_int (algo));
  if (err)
    {
      return SCM_BOOL_F;
    }
  err = gcry_md_enable (hd, scm_to_int (algo));
  if (err)
    {
      return SCM_BOOL_F;
    }
  return SCM_BOOL_T;  
}
#undef FUNC_NAME

/* SCM_DEFINE (scm_gcry_md_setkey, "set-key", 2, 0, 0, */
/* 	    (SCM hobj, SCM key_bv), "") */
/* #define FUNC_NAME "scm_gcry_md_setkey" */
/* { */
/*   return SCM_BOOL_F; */
/* } */
/* #undef FUNC_NAME */

/* SCM_DEFINE (scm_gcry_md_close, "md-close", 1, 0, 0, */
/* 	    (SCM hobj), "") */
/* #define FUNC_NAME "scm_gcry_md_close" */
/* { */
/*   gcry_md_hd_t hd; */
/*   scm_assert_smob_type (gcry_md_hd_t_tag, hobj); */
/*   hd = (gcry_md_hd_t) SCM_SMOB_DATA (hobj); */
  
/*   gcry_md_close (hd); */
/*   //  HASHOBJ_CLOSE (hd); */
  
/*   return SCM_BOOL_T; */
/* } */
/* #undef FUNC_NAME */

SCM_DEFINE (scm_gcry_md_reset, "reset", 1, 0, 0,
	    (SCM hobj), "")
#define FUNC_NAME "scm_gcry_md_reset"
{
  gcry_md_hd_t hd;
  scm_assert_smob_type (gcry_md_hd_t_tag, hobj);
  hd = (gcry_md_hd_t) SCM_SMOB_DATA (hobj);
  gcry_md_reset (hd);
  return SCM_BOOL_T;
}
#undef FUNC_NAME

/* SCM_DEFINE (scm_gcry_md_copy, "copy", 2, 0, 0, */
/* 	    (SCM src_hobj, SCM dest_hobj), "") */
/* #define FUNC_NAME "scm_gcry_md_copy" */
/* { */
/*   return SCM_BOOL_F; */
/* } */
/* #undef FUNC_NAME */

SCM_DEFINE (scm_gcry_md_write, "write", 2, 0, 0,
	    (SCM hobj, SCM bv), "")
#define FUNC_NAME "scm_gcry_md_write"
{
  gcry_md_hd_t hd;
  void * buf;
  size_t buflen;
  
  scm_assert_smob_type (gcry_md_hd_t_tag, hobj);
  SCM_ASSERT(scm_bytevector_p (bv), bv, SCM_ARG2, FUNC_NAME);
  
  hd = (gcry_md_hd_t) SCM_SMOB_DATA (hobj);
  buf = (void *) SCM_BYTEVECTOR_CONTENTS (bv);
  buflen = SCM_BYTEVECTOR_LENGTH (bv);

  gcry_md_write (hd, buf, buflen);
  return SCM_BOOL_T;
}
#undef FUNC_NAME

SCM_DEFINE (scm_gcry_md_read, "read", 1, 1, 0,
	    (SCM hobj, SCM algo), "")
#define FUNC_NAME "scm_gcry_md_read"
{
  gcry_md_hd_t hd;
  int _algo = 0;
  unsigned char * hash;
  SCM hash_bv;
  unsigned int dlen;
  
  scm_assert_smob_type (gcry_md_hd_t_tag, hobj);
  if (! SCM_UNBNDP (algo))
    {
      SCM_ASSERT(scm_integer_p (algo), algo, SCM_ARG2, FUNC_NAME);
      _algo = scm_to_int (algo);
    }

  hd = (gcry_md_hd_t) SCM_SMOB_DATA (hobj);

  hash = gcry_md_read (hd, _algo);
  if (hash == NULL)
    {
      return SCM_EOL;
    }
  dlen = (_algo) ? gcry_md_get_algo_dlen(_algo) : gcry_md_get_algo_dlen(gcry_md_get_algo(hd));

  hash_bv = scm_c_make_bytevector (dlen);
  memcpy ((void *) SCM_BYTEVECTOR_CONTENTS (hash_bv), hash, dlen);
  
  return hash_bv;
}
#undef FUNC_NAME

SCM_DEFINE (scm_gcry_test_algo, "test-algo", 1, 0, 0,
	    (SCM algo), "")
#define FUNC_NAME "scm_gcry_test_algo"
{
  return SCM_BOOL_F;
}
#undef FUNC_NAME

SCM_DEFINE (scm_gcry_is_enabled, "enabled?", 2, 0, 0,
	    (SCM hobj, SCM algo), "")
#define FUNC_NAME "scm_gcry_is_enabled"
{
  gcry_md_hd_t hd;
  scm_assert_smob_type (gcry_md_hd_t_tag, hobj);
  SCM_ASSERT (scm_integer_p (algo), algo, SCM_ARG2, FUNC_NAME);
  hd = (gcry_md_hd_t) SCM_SMOB_DATA (hobj);

  return gcry_md_is_enabled (hd, scm_to_int (algo)) ? SCM_BOOL_T : SCM_BOOL_F;
}
#undef FUNC_NAME

/* ;; gcry_md_putc */
/* ;; gcry_md_final */
/* ;; gcry_md_get_asnoid */
/* ;; gcry_md_is_secure */

static size_t
free_hash_smob (SCM smob)
{
  gcry_md_hd_t hd = (gcry_md_hd_t) SCM_SMOB_DATA (smob);
  gcry_md_close (hd);
  return 0;
}

static int
print_hash_smob (SCM smob, SCM port, scm_print_state * pstate)
{
  gcry_md_hd_t hd = (gcry_md_hd_t) SCM_SMOB_DATA (smob);
  scm_puts("#<", port);
  if (HASHOBJ_OPEN_P (hd))
    {
      scm_puts (gcry_md_algo_name (gcry_md_get_algo (hd)), port);
      scm_puts (" HASH OBJECT ", port);
      scm_uintprint (SCM_CELL_WORD_1 (smob), 16, port);
      scm_putc ('>', port);
    }
  else
    {
      scm_puts ("CLOSED HASH OBJ>", port);
      return 1;
    }
  return 1;
}

static void
init_smob(void)
{
  gcry_md_hd_t_tag = scm_make_smob_type ("gcrypt-hash-object", sizeof(gcry_md_hd_t));
  scm_set_smob_free (gcry_md_hd_t_tag, free_hash_smob);
  scm_set_smob_print (gcry_md_hd_t_tag, print_hash_smob);
}

void
gcrypt_guile_init()
{
  if (!gcry_check_version (GCRYPT_VERSION))
    {
      fputs ("libgcrypt version mismatch\n", stderr);
      exit (EXIT_FAILURE);
    }
  init_smob();
  #include "hash.x"
}
