#include <stdio.h>
#include <stdlib.h>

#include <gcrypt.h>
#include <libguile.h>


static void
inner_main (void *closure, int argc, char **argv)
{
  /* module initializations would go here */
  scm_shell (argc, argv);
}

int
main (int argc, char **argv)
{
  if (!gcry_check_version (NULL))
    {
      fprintf(stderr, "libgcrypt version mismatch\n");
      exit(EXIT_FAILURE);
    }
      
  scm_boot_guile (argc, argv, inner_main, 0);
  return 0;
}
