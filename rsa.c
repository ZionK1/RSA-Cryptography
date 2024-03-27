// clang-format off
#include <stdio.h>
#include <gmp.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include "rsa.h"
#include "numtheory.h"
#include "randstate.h"
// clang-format on

// creates parts of a new RSA public key: primes p and q, product n, public
// exponent e
void rsa_make_pub(mpz_t p, mpz_t q, mpz_t n, mpz_t e, uint64_t nbits,
                  uint64_t iters) {
  uint64_t pbits = random() % ((2 * nbits)/4) + nbits/4;
  uint64_t qbits = nbits - pbits;
  make_prime(p, pbits + 1, iters); // make prime p
  make_prime(q, qbits + 1, iters); // make prime q
  mpz_mul(n, p, q);
  mpz_t psub1, qsub1, phi_n, rand, d, lamn;
  mpz_inits(psub1, qsub1, phi_n, rand, d, lamn,
            NULL);               // initialize used mpz vars
  mpz_sub_ui(psub1, p, 1);       // psub1 = p - 1
  mpz_sub_ui(qsub1, q, 1);       // qsub1 = q - 1
  mpz_mul(phi_n, psub1, qsub1);  // phi_n = (p-1)(q-1)
  gcd(lamn, psub1, qsub1);       // store gcd(p-1)(q-1) in n
  mpz_fdiv_q(lamn, phi_n, lamn); // n = phi_n / gcd(p-1)(q-1) 
  while (true) {
    mpz_urandomb(rand, state, nbits); // generate random num in rand mpz var
    gcd(d, rand, lamn);          // check for gcd of generated rand num and n
    if (mpz_cmp_ui(d, 1) == 0) { // if rand num and n are coprime
      mpz_set(e, rand);          // set public exponent as rand
      mpz_clears(psub1, qsub1, phi_n, rand, d, lamn, NULL); // clear mpzs
      return;
    }
  }
}

// writes public RSA key to pbfile
void rsa_write_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
  gmp_fprintf(pbfile, "%Zx\n%Zx\n%Zx\n", n, e, s);
  fprintf(pbfile, "%s\n", username);
}

// reads a public RSA key from pbfile
void rsa_read_pub(mpz_t n, mpz_t e, mpz_t s, char username[], FILE *pbfile) {
  gmp_fscanf(pbfile, "%Zx\n%Zx\n%Zx\n%s\n", n, e, s, username);
}

// creates a new RSA private key given p, q, and e
void rsa_make_priv(mpz_t d, mpz_t e, mpz_t p, mpz_t q) {
  mpz_t lamn, psub1, qsub1, phi_n;
  mpz_inits(lamn, psub1, qsub1, phi_n, NULL);
  mpz_sub_ui(psub1, p, 1);       // psub1 = p - 1
  mpz_sub_ui(qsub1, q, 1);       // qsub1 = q - 1
  mpz_mul(phi_n, psub1, qsub1);  // phi_n = (p-1)(q-1)
  gcd(lamn, psub1, qsub1);       // store gcd(p-1)(q-1) in lamn
  mpz_fdiv_q(lamn, phi_n, lamn); // n = phi_n / gcd(p-1)(q-1)
  mod_inverse(d, e, lamn);
  mpz_clears(lamn, psub1, qsub1, phi_n, NULL); // clear mpzs
}

// writes private RSA key to pvfile
void rsa_write_priv(mpz_t n, mpz_t d, FILE *pvfile) {
  gmp_fprintf(pvfile, "%Zx\n%Zx\n", n, d);
}

// reads a private RSA key from pvfile
void rsa_read_priv(mpz_t n, mpz_t d, FILE *pvfile) {
  gmp_fscanf(pvfile, "%Zx\n%Zx\n", n, d);
}

// performs RSA encryption, computing ciphertext c
void rsa_encrypt(mpz_t c, mpz_t m, mpz_t e, mpz_t n) { pow_mod(c, m, e, n); }

// encrypts contents of infile, writing encrypted contents to outfile
void rsa_encrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t e) {
  mpz_t m, c, mk;
  mpz_inits(m, c, mk,
            NULL); // initialize mpz m for message and mpz c for ciphertext
  uint64_t logn = mpz_sizeinbase(n, 2) - 1; // logn = log base 2 (n) - 1
  mpz_set_ui(mk, logn);
  mpz_fdiv_q_ui(mk, mk, 8); // k = floordiv(log base 2 (n) - 1)/8
  uint64_t k = mpz_get_ui(mk);
  uint64_t b = 0;             // bytes
  fseek(infile, 0, SEEK_END); // seek end of file and ask for position (to find
                              // number of bytes)
  b = ftell(infile);          // check for total number of bytes in infile
  fseek(infile, 0, SEEK_SET); // set position in file to beginning
  uint64_t bleft = 0;         // bytes left to read
  size_t bytes_read = 1;      // number of bytes actually read
  uint64_t i = 1;             // index
  while (
      bytes_read >
      0) { // while not at end of file or there are unprocessed bytes in infile
    uint8_t *block = (uint8_t *)calloc(
        k, sizeof(uint8_t)); // dynamically allocate array of k bytes
    if (!block) {            // if block is empty
      free(block);
      block = NULL; // clear block
    }
    block[0] = 0xFF; // set 0th index(byte) of block as 0xFF
    if (b >= b - (k - 1)) {   // if bytes in file >= bytes in file - (size of block - 1)
      bleft = k - 1; // read k - 1 bytes
    } else {
      bleft = b - i; // do not read k - 1 bytes
    }
    if (bleft == 0) { // if there are no bytes left to read
      free(block);
      block = NULL; // clear block
      break;
    }
    bytes_read =
        fread(block + 1, sizeof(uint8_t), bleft,
              infile); // bytes_read = number of bytes read through fread
    i += bytes_read;   // increment index by number of bytes read
    mpz_import(m, bytes_read + 1, 1, 1, 1, 0,
               block);       // import block and create m
    rsa_encrypt(c, m, e, n); // encrypt m into ciphertext c
    gmp_fprintf(outfile, "%Zx\n",
                c); // print ciphertext to outfile as hexstring
    free(block);
    block = NULL; // clear block
  }
  mpz_clears(m, c, NULL); // clear used mpzs
}

// performs rsa decryption, computing msg m by decrypting ciphertext c using
// priv key d and pub modulus n
void rsa_decrypt(mpz_t m, mpz_t c, mpz_t d, mpz_t n) { pow_mod(m, c, d, n); }

// decrypts the content of infile, writing the decrypted contents to outfile
void rsa_decrypt_file(FILE *infile, FILE *outfile, mpz_t n, mpz_t d) {
  mpz_t c, m, mk;
  mpz_inits(c, m, mk, NULL);                // initialize used mpz vars
  uint64_t logn = mpz_sizeinbase(n, 2) - 1; // logn = log base 2 (n) - 1
  mpz_set_ui(mk, logn);
  mpz_fdiv_q_ui(mk, mk, 8); // k = floordiv(log base 2 (n) - 1)/8
  uint64_t k = mpz_get_ui(mk);
  size_t j = 0; // used later for bytes converted from message
  while (1) {   // while not at end of file
    uint8_t *block = (uint8_t *)calloc(
        k, sizeof(uint8_t)); // dynamically allocate array of k bytes
    if (feof(infile)) {      // if end of file is reached / all bytes processed
      free(block);
      block = NULL; // clear block
      break;        // exit out of while loop
    }
    gmp_fscanf(infile, "%Zx\n",
               c);           // scan in a hexstring, saving it to c (ciphertext)
    rsa_decrypt(m, c, d, n); // decrypt ciphertext c and store in message m
    mpz_export(block, &j, 1, 1, 1, 0,
               m); // convert message into bytes, stored them into block
    fwrite(block + 1, sizeof(uint8_t), j - 1,
           outfile); // write out j - 1 bytes starting from index 1 of block to
                     // outfile
    free(block);
    block = NULL; // clear block
  }
  mpz_clears(c, m, NULL); // clear used mpz vars
}

// performs rsa signing, producing signature s by signing msg m using priv key d
// and pub modulus n
void rsa_sign(mpz_t s, mpz_t m, mpz_t d, mpz_t n) { pow_mod(s, m, d, n); }

// performs rsa verification, returning true if signature s is verified and
// false otherwise
bool rsa_verify(mpz_t m, mpz_t s, mpz_t e, mpz_t n) {
  mpz_t t;
  mpz_init(t);         // initialize tmp mpz var
  pow_mod(t, s, e, n); // reverse sign
  if (mpz_cmp(t, m) == 0) {
    mpz_clear(t); // clear tmp mpz var
    return true;  // t = m signature is verified
  } else {
    mpz_clear(t); // clear tmp mpz var
    return false; // t != m signature is not verified
  }
}
