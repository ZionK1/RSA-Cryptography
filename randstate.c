#include "randstate.h"
#include <stdint.h>
// clang-format off
#include <stdio.h>
#include <gmp.h>
// clang-format on
#include <stdlib.h>

gmp_randstate_t state;

// initialize rand state with Mersenne Twister algorithm and setting random seed
void randstate_init(uint64_t seed) {
  srandom(seed);                // set seed for mpz random
  gmp_randinit_mt(state);       // initialize gmp mersenne twister algorithm
  gmp_randseed_ui(state, seed); // set seed for gmp random
}

// clear and free memory used by randstate
void randstate_clear(void) {
  gmp_randclear(state); // clear gmp rand state
}
