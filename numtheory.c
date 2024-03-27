// clang-format off
#include <stdio.h>
#include <gmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "randstate.h"
// clang-format on

// computes a raised to d modulo n, stored in o
void pow_mod(mpz_t o, mpz_t a, mpz_t d, mpz_t n) {
  mpz_t v, p, dcopy;
  mpz_init_set_ui(v, 1); // set v = 1
  mpz_init_set(p, a);    // set p = a
  mpz_init_set(dcopy, d);
  while (mpz_cmp_ui(dcopy, 0) > 0) { // while d > 0
    if (mpz_odd_p(dcopy) != 0) {     // if d is odd
      mpz_mul(v, v, p);              // v = (v x p)
      mpz_mod(v, v, n);              // v = v mod n
    }
    mpz_mul(p, p, p);               // p = (p x p)
    mpz_mod(p, p, n);               // p = p mod n
    mpz_fdiv_q_ui(dcopy, dcopy, 2); // d = d/2
  }
  mpz_set(o, v);                 // o = v
  mpz_clears(v, p, dcopy, NULL); // clear used mpzs
}

// conducts miller-rabin primality test to indicate if n is prime using iters
// number of iterations
bool is_prime(mpz_t n, uint64_t iters) {
  mpz_t r, s, i, k;
  mpz_inits(r, s, NULL);
  mpz_sub_ui(r, n, 1);         // init r as n - 1
  while (mpz_even_p(r) == 0) { // if r is odd
    mpz_add_ui(s, s, 1);       // inc s by 1
    mpz_fdiv_q_ui(r, r, 2);    // div r by 2
  }
  mpz_init_set_ui(i, 1);
  mpz_init_set_ui(k, iters);
  while (mpz_cmp(i, k) <= 0) {
    mpz_t a, nsub3, y, nsub1;
    mpz_inits(a, nsub3, y, nsub1, NULL);
    mpz_sub_ui(nsub3, n, 3); // n - 3
    mpz_init_set_ui(
        a, gmp_urandomm_ui(state,
                           mpz_get_ui(nsub3))); // set a = ran # from 0 to n - 4
    mpz_add_ui(a, a, 2);     // add 2 to a so range is from 2 to n - 2
    pow_mod(y, a, r, n);     // set y = pow_mod(a, r, n)
    mpz_sub_ui(nsub1, n, 1); // n - 1 for checking conditions in while loop
    if (mpz_cmp_ui(y, 1) != 0 && mpz_cmp(y, nsub1) != 0) {
      mpz_t j;
      mpz_init_set_ui(j, 1);
      mpz_t ssub1;
      mpz_init(ssub1);
      mpz_sub_ui(ssub1, s, 1); // s - 1 for checking conditions in while loop
      mpz_t d;
      mpz_init_set_ui(d, 2); // mpz_t d = 2 for pass into pow_mod
      while (mpz_cmp(j, ssub1) <= 0 && mpz_cmp(y, nsub1) != 0) {
        pow_mod(y, y, d, n); // y = pow_mod(y, 2, n)
        if (mpz_cmp_ui(y, 1) == 0) {
          mpz_clears(r, s, i, k, a, nsub3, y, nsub1, ssub1, j, d,
                     NULL); // clear used mpzs
          return false;
        }
        mpz_add_ui(j, j, 1);
      }
      if (mpz_cmp(y, nsub1) != 0) {
        mpz_clears(r, s, i, k, a, nsub3, y, nsub1, ssub1, j,
                   NULL); // clear used mpzs
        return false;
      }
    }
    mpz_add_ui(i, i, 1);
  }
  mpz_clears(r, s, i, k, NULL); // clear used mpzs
  return true;
}

// use urandomb for makeprime
void make_prime(mpz_t p, uint64_t bits, uint64_t iters) {
  while (true) {                  // looping until prime is made
    mpz_urandomb(p, state, bits); // generate random num
    if (is_prime(p, iters) && mpz_sizeinbase(p, 2) >= bits - 1) {     // check if random num is prime
      return;
    }
  }
}

// computes greatest common divisor of a and b, storing value of computed
// divisor in d
void gcd(mpz_t d, mpz_t a, mpz_t b) {
  mpz_t t, acopy, bcopy;
  mpz_inits(t, acopy, bcopy, NULL);
  mpz_set(acopy, a);
  mpz_set(bcopy, b);
  while (mpz_cmp_ui(bcopy, 0) != 0) {
    mpz_set(t, bcopy);            // t = b
    mpz_mod(bcopy, acopy, bcopy); // b = a mod b
    mpz_set(acopy, t);            // a = t
  }
  mpz_set(d, acopy); // store gcd in d
  mpz_clears(t, acopy, bcopy, NULL);
}

// computes inverse o of a modulo n (if modular inverse cannot be found o = 0)
void mod_inverse(mpz_t o, mpz_t a, mpz_t n) {
  mpz_t r1, r2, t1, t2;
  mpz_init_set(r1, n);    // r1 = n
  mpz_init_set(r2, a);    // r2 = a
  mpz_init_set_si(t1, 0); // t1 = 0
  mpz_init_set_si(t2, 1); // t2 = 1
  while (mpz_cmp_ui(r2, 0) != 0) {
    mpz_t q;
    mpz_init(q);
    mpz_fdiv_q(q, r1, r2); // q = r1/r2 (fdiv)
    mpz_t rtmp, rtmp2;
    mpz_init_set(rtmp, r1); // rtmp = r1
    mpz_set(r1, r2);        // r1 = r2
    mpz_init(rtmp2);
    mpz_mul(rtmp2, q, r2);       // rtmp2 = q x r2
    mpz_sub(rtmp2, rtmp, rtmp2); // rtmp2 = r1 - (q x r2)
    mpz_set(r2, rtmp2);          // r2 = r1 - q x r2
    mpz_t ttmp, ttmp2;
    mpz_init_set(ttmp, t1); // ttmp = t1
    mpz_set(t1, t2);        // t1 = t2
    mpz_init(ttmp2);
    mpz_mul(ttmp2, q, t2);       // ttmp2 = q x t2
    mpz_sub(ttmp2, ttmp, ttmp2); // ttmp2 = t1 - (q x t2)
    mpz_set(t2, ttmp2);          // t2 = t1 - q x t2
    mpz_clears(q, rtmp, rtmp2, ttmp, ttmp2, NULL);
  }
  if (mpz_cmp_si(r1, 1) > 0) {
    mpz_set_ui(o, 0);                 // o = 0
    mpz_clears(r1, r2, t1, t2, NULL); // clear used mpzs before return
    return;
  }
  if (mpz_cmp_si(t1, 0) < 0) {
    mpz_add(t1, t1, n); // t1 = t1 + n
  }
  mpz_set(o, t1);                   // o = t1
  mpz_clears(r1, r2, t1, t2, NULL); // clear used mpzs at end of fxn
}
