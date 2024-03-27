// clang-format off
#include <stdio.h>
#include <gmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "numtheory.h"
#include "randstate.h"
#include "rsa.h"
// clang-format on

#define OPTIONS "i:o:n:vh" // options

int main(int argc, char **argv) {
  // declare files for encrypting
  FILE *infile = stdin;
  FILE *outfile = stdout;
  FILE *pbfile;
  bool verbose = false;
  bool user_set_file = false;
  int32_t opt = 0;
  while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
    switch (opt) {
    case 'h': // print help msg
      fprintf(stderr, "Usage: ./encrypt [options]\n");
      fprintf(stderr, "  ./encrypt encrypts an input file using the specified "
                      "public key file,\n");
      fprintf(stderr, "  writing the result to the specified output file.\n");
      fprintf(stderr, "    -i <infile> : Read input from <infile>. Default: "
                      "standard input.\n");
      fprintf(stderr, "    -o <outfile>: Write output to <outfile>. Default: "
                      "standard output.\n");
      fprintf(
          stderr,
          "    -n <keyfile>: Public key is in <keyfile>. Default: rsa.pub.\n");
      fprintf(stderr, "    -v          : Enable verbose output.\n");
      fprintf(stderr,
              "    -h          : Display program synopsis and usage.\n");
      return 0;
    case 'v':
      verbose = true; // enable verbose output
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
      pbfile = fopen(optarg, "r");
      if (pbfile == NULL) {
        printf("pbfile couldn't be opened\n");
        return 1;
      }
      user_set_file = true;
      break;
    default:
      fprintf(stderr, "Usage: ./encrypt [options]\n");
      fprintf(stderr, "  ./encrypt encrypts an input file using the specified "
                      "public key file,\n");
      fprintf(stderr, "  writing the result to the specified output file.\n");
      fprintf(stderr, "    -i <infile> : Read input from <infile>. Default: "
                      "standard input.\n");
      fprintf(stderr, "    -o <outfile>: Write output to <outfile>. Default: "
                      "standard output.\n");
      fprintf(
          stderr,
          "    -n <keyfile>: Public key is in <keyfile>. Default: rsa.pub.\n");
      fprintf(stderr, "    -v          : Enable verbose output.\n");
      fprintf(stderr,
              "    -h          : Display program synopsis and usage.\n");
      return 1;
    }
  }
  if (!user_set_file) {             // if user hasn't set pbfile
    pbfile = fopen("rsa.pub", "r"); // Open the public key file.
  }

  mpz_t n, e, s, username;
  mpz_inits(n, e, s, username, NULL);
  char *userid = getenv("USER"); // get userid

  rsa_read_pub(n, e, s, userid, pbfile); // read public key from open pbfile

  if (verbose) { // if verbose output is enabled print the following
    printf("username: %s\n", userid);
    gmp_printf("user signature (%d bits): %Zd\n", mpz_sizeinbase(s, 2), s);
    gmp_printf("n - modulus (%d bits): %Zd\n", mpz_sizeinbase(n, 2), n);
    gmp_printf("e - public exponent (%d bits): %Zd\n", mpz_sizeinbase(e, 2), e);
  }

  mpz_set_str(username, userid, 62); // convert  username to mpz_t
  if (!rsa_verify(username, s, e,
                  n)) { // verify signature and if signature is not verified
    fprintf(stderr, "Error: Cannot be verified\n"); // print error msg
    mpz_clears(n, e, s, username, NULL);            // clear mpz vars
    fclose(infile);
    fclose(outfile);
    fclose(pbfile); // close files
    return 1;       // return non zero exit code
  }

  rsa_encrypt_file(infile, outfile, n, e); // encrypt file
  fclose(infile);
  fclose(outfile);
  fclose(pbfile);
  mpz_clears(n, e, s, username, NULL); // close files and clear mpz vars used
  return 0;
}
