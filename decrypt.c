// clang-format off
#include <stdio.h>
#include <gmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"
// clang-format on

#define OPTIONS "i:o:n:vh"

int main(int argc, char **argv) {
  // declare files for decrypting
  FILE *infile = stdin;
  FILE *outfile = stdout;
  FILE *pvfile;
  bool verbose = false; // default for verbose output = false
  bool user_set_file = false;
  int32_t opt = 0;
  while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
    switch (opt) {
    case 'v':
      verbose = true;
      break;
    case 'i':
      infile = fopen(optarg, "r");
      if (infile == NULL) {
        fprintf(stderr, "infile couldn't be opened\n");
        return 1;
      }
      break;
    case 'o':
      outfile = fopen(optarg, "w");
      if (outfile == NULL) {
        fprintf(stderr, "outfile couldn't be opened\n");
        return 1;
      }
      break;
    case 'n':
      pvfile = fopen(optarg, "r");
      if (pvfile == NULL) {
        printf("pvfile couldn't be opened\n");
        return 1;
      }
      user_set_file = true;
      break;
    case 'h':
      fprintf(stderr, "Usage: ./decrypt [options]\n");
      fprintf(stderr, "  ./decrypt decrypts an input file using the specified "
                      "private key file,\n");
      fprintf(stderr, "  writing the result to the specified output file.\n");
      fprintf(stderr, "    -i <infile> : Read input from <infile>. Default: "
                      "standard input.\n");
      fprintf(stderr, "    -o <outfile>: Write output to <outfile>. Default: "
                      "standard output.\n");
      fprintf(stderr, "    -n <keyfile>: Private key is in <keyfile>. Default: "
                      "rsa.priv.\n");
      fprintf(stderr, "    -v          : Enable verbose output.\n");
      fprintf(stderr,
              "    -h          : Display program synopsis and usage.\n");
      return 0;
    default:
      fprintf(stderr, "Usage: ./decrypt [options]\n");
      fprintf(stderr, "  ./decrypt decrypts an input file using the specified "
                      "private key file,\n");
      fprintf(stderr, "  writing the result to the specified output file.\n");
      fprintf(stderr, "    -i <infile> : Read input from <infile>. Default: "
                      "standard input.\n");
      fprintf(stderr, "    -o <outfile>: Write output to <outfile>. Default: "
                      "standard output.\n");
      fprintf(stderr, "    -n <keyfile>: Private key is in <keyfile>. Default: "
                      "rsa.priv.\n");
      fprintf(stderr, "    -v          : Enable verbose output.\n");
      fprintf(stderr,
              "    -h          : Display program synopsis and usage.\n");
      return 1;
    }
  }

  if (user_set_file == false) {      // if user has not set pvfile
    pvfile = fopen("rsa.priv", "r"); // open priv key file
  }

  mpz_t n, d;
  mpz_inits(n, d,
            NULL); // initialize mpz vars for public modulus n and priv key d
  rsa_read_priv(n, d, pvfile); // read from opened priv key file

  if (verbose) { // if verbose output is enabled
    gmp_printf("n - modulus (%d bits): %Zd\n", mpz_sizeinbase(n, 2), n);
    gmp_printf("d - modulus (%d bits): %Zd\n", mpz_sizeinbase(d, 2), d);
  }

  rsa_decrypt_file(infile, outfile, n, d); // decrypt file

  fclose(infile);
  fclose(outfile);
  fclose(pvfile);         // close used files
  mpz_clears(n, d, NULL); // clear mpz vars
  return 0;
}
