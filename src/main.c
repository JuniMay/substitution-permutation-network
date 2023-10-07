#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"

const size_t L = 4;
const size_t M = 4;
const size_t NR = 4;

/// Substitution parameters
const uint8_t PI_S[16] = {0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
                          0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7};

/// Permutation parameters
const uint8_t PI_P[16] = {0x0, 0x4, 0x8, 0xC, 0x1, 0x5, 0x9, 0xD,
                          0x2, 0x6, 0xA, 0xE, 0x3, 0x7, 0xB, 0xF};

static uint32_t key = 0;

/// Memory layout of a grouped `u`.
typedef struct {
  uint16_t a : 4;
  uint16_t b : 4;
  uint16_t c : 4;
  uint16_t d : 4;
} Group;

/// Generate a key for the `r`-th round
uint16_t generate_key(size_t r) {
  return (key << (4 * r - 4)) >> 16;
}

/// Group-wise substitution
uint16_t substitute(uint16_t u) {
  uint16_t v = 0;
  Group* g = (Group*)(&u);
  Group* h = (Group*)(&v);

  h->a = PI_S[g->a];
  h->b = PI_S[g->b];
  h->c = PI_S[g->c];
  h->d = PI_S[g->d];

  return v;
}

/// Bitwise permutation
///
/// The highest bit in the number is the first bit in the array.
/// The `PI_P` should be applied in reverse order.
uint16_t permute(uint16_t v) {
  uint16_t w = 0;

  for (size_t i = 0; i < 16; i++) {
    uint16_t bit = (v & (0x8000 >> i)) != 0;
    w |= bit << (15 - PI_P[i]);
  }

  return w;
}

/// Encryption
uint16_t encrypt(uint16_t plaintext) {
  uint16_t w = plaintext;
  uint16_t u, v, key;

  for (size_t r = 1; r <= NR - 1; r++) {
    key = generate_key(r);
    u = w ^ key;
    v = substitute(u);
    w = permute(v);
  }

  key = generate_key(NR);
  u = w ^ key;
  v = substitute(u);

  key = generate_key(NR + 1);
  uint16_t ciphertext = v ^ key;

  return ciphertext;
}

int main(int argc, char* argv[]) {
  uint16_t x = 0;
  uint32_t k = 0;

  char str[33];

  scanf("%s", str);
  for (size_t i = 0; i < 16; i++) {
    x <<= 1;
    x |= str[i] == '1';
  }

  scanf("%s", str);
  for (size_t i = 0; i < 32; i++) {
    k <<= 1;
    k |= str[i] == '1';
  }

  key = k;

  uint16_t y = encrypt(x);

  // print by bit for y
  for (size_t i = 0; i < 16; i++) {
    printf("%d", (y & (0x8000 >> i)) != 0);
  }

  // printf("\n");

  return 0;
}