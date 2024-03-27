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

#define OPTIONS "hb:i:n:d:s:v"

int main(int argc, char **argv) {
  FILE *pbfile;
  FILE *pvfile;
  uint64_t nbits =
      1024;            // default number of bits needed for public mod n = 1024
  uint64_t iters = 50; // default iters for testing primes = 50
  uint32_t seed = time(NULL); // default seed = time(NULL)
  bool verbose = false;       // default for verbose output = false
  bool user_set_pbfile = false;
  bool user_set_pvfile = false;
  int64_t opt = 0;
  while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
    switch (opt) {
    case 'h': // print help msg and return successful exit code
      fprintf(stderr, "Usage: ./keygen [options]\n");
      fprintf(stderr, "  ./keygen generates a public / private key pair, "
                      "placing the keys into the public and private\n");
      fprintf(stderr, "  key files as specified below. The keys have a modulus "
                      "(n) whose length is specified in\n");
      fprintf(stderr, "  the program options.\n");
      fprintf(stderr, "    -s <seed>   : Use <seed> as the random number seed. "
                      "Default: time()\n");
      fprintf(stderr, "    -b <bits>   : Public modulus n must have at least "
                      "<bits> bits. Default: 1024\n");
      fprintf(stderr, "    -i <iters>  : Run <iters> Miller-Rabin iterations "
                      "for primality testing. Default: 50\n");
      fprintf(
          stderr,
          "    -n <pbfile> : Public key file is <pbfile>. Default: rsa.pub\n");

      fprintf(stderr, "    -d <pvfile> : Private key file is <pvfile>. "
                      "Default: rsa.priv\n");
      fprintf(stderr, "    -v          : Enable verbose output.\n");
      fprintf(stderr,
              "    -h          : Display program synopsis and usage.\n");
      return 0;
    case 'b':
      nbits = strtoul(optarg, NULL, 10); // setting nbits to optarg
      break;
    case 'i':
      iters = strtoul(optarg, NULL, 10); // setting iters to optarg
    case 'n':
      pbfile = fopen(optarg, "w+"); // open pbfile set by user
      if (pbfile == NULL) {         // if pbfile doesnt exist
        fprintf(stderr, "pbfile couldn't be opened\n");
        return 1;
      }
      user_set_pbfile = true; // user has set file for public key
      break;
    case 'd':
      pvfile = fopen(optarg, "w+"); // open pvfile set by user
      if (pvfile == NULL) {         // if pvfile doesn't exist
        fprintf(stderr, "pvfile couldn't be opened\n");
        return 1;
      }
      user_set_pvfile = true; // user has set file for private key
      break;
    case 's':
      seed = strtoul(optarg, NULL, 10);
      break;
    case 'v':
      verbose = true;
      break;
    default: // on bad arg print help msg and return non zero exit code
      fprintf(stderr, "Usage: ./keygen [options]\n");
      fprintf(stderr, "  ./keygen generates a public / private key pair, "
                      "placing the keys into the public and private\n");
      fprintf(stderr, "  key files as specified below. The keys have a modulus "
                      "(n) whose length is specified in\n");
      fprintf(stderr, "  the program options.\n");
      fprintf(stderr, "    -s <seed>   : Use <seed> as the random number seed. "
                      "Default: time()\n");
      fprintf(stderr, "    -b <bits>   : Public modulus n must have at least "
                      "<bits> bits. Default: 1024\n");
      fprintf(stderr, "    -i <iters>  : Run <iters> Miller-Rabin iterations "
                      "for primality testing. Default: 50\n");
      fprintf(
          stderr,
          "    -n <pbfile> : Public key file is <pbfile>. Default: rsa.pub\n");

      fprintf(stderr, "    -d <pvfile> : Private key file is <pvfile>. "
                      "Default: rsa.priv\n");
      fprintf(stderr, "    -v          : Enable verbose output.\n");
      fprintf(stderr,
              "    -h          : Display program synopsis and usage.\n");
      return 1;
    }
  }
  if (user_set_pbfile ==
      false) { // if user hasn't set pbfile open default pbfile
    pbfile = fopen("rsa.pub", "w+");
    if (pbfile == NULL) {
      fprintf(stderr, "pbfile couldn't be opened\n");
      return 1;
    }
  }
  if (user_set_pvfile ==
      false) { // if user hasn't set pvfile open default pvfile
    pvfile = fopen("rsa.priv", "w+");
    if (pvfile == NULL) {
      fprintf(stderr, "pvfile couldn't be opened\n");
      return 1;
    }
  }
  int pv = fileno(pvfile); // run fileno to identify pvfile
  fchmod(pv, 0600);        // set private key file permissions for user only
  randstate_init(seed);    // initialize rand state and set seed

  mpz_t p, q, n, e, d, username, s;
  mpz_inits(p, q, n, e, d, username, s,
            NULL); // initialize mpz vars for pub and priv keys
  rsa_make_pub(p, q, n, e, nbits, iters); // make pub key
  rsa_make_priv(d, e, p, q);              // make priv key

  char *userid = getenv("USER"); // get current username's name as string
  mpz_set_str(username, userid,
              62);             // convert username into mpz with base of 62
  rsa_sign(s, username, d, n); // computer signature of username
  rsa_write_pub(n, e, s, userid, pbfile); // write computed public key to pbfile
  rsa_write_priv(n, d, pvfile); // write computed private key to pvfile

  if (verbose) { // if verbose output is enabled print
    fprintf(stderr, "username = %s\n", userid);
    gmp_fprintf(stderr, "user signature (%d bits): %Zd\n", mpz_sizeinbase(s, 2),
                s);
    gmp_fprintf(stderr, "p (%d bits): %Zd\n", mpz_sizeinbase(p, 2), p);
    gmp_fprintf(stderr, "q (%d bits): %Zd\n", mpz_sizeinbase(q, 2), q);
    gmp_fprintf(stderr, "n - modulus (%d bits): %Zd\n", mpz_sizeinbase(n, 2),
                n);
    gmp_fprintf(stderr, "e - public exponent (%d bits): %Zd\n",
                mpz_sizeinbase(e, 2), e);
    gmp_fprintf(stderr, "d - private exponent (%d bits): %Zd\n",
                mpz_sizeinbase(d, 2), d);
  }

  fclose(pbfile);
  fclose(pvfile);
  randstate_clear();
  mpz_clears(p, q, n, e, d, username, s, NULL);
  return 0;
}
