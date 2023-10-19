#include "stdbool.h"
#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "sys/time.h"

const size_t NR = 4;

/// Inverse substitution parameters
const uint8_t PI_S_INV[16] = {0xE, 0x3, 0x4, 0x8, 0x1, 0xC, 0xA, 0xF,
                              0x7, 0xD, 0x9, 0x6, 0xB, 0x2, 0x0, 0x5};

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

  // printf("key_5: %d\n", key);

  uint16_t ciphertext = v ^ key;

  return ciphertext;
}

/// Linear attack
uint32_t
linear_attack(size_t size, uint16_t* plaintexts, uint16_t* ciphertexts) {
  size_t count[256];
  for (size_t i = 0; i <= 0xff; i++) {
    count[i] = 0;
  }

  for (size_t i = 0; i < size; i++) {
    uint16_t x = plaintexts[i];
    uint16_t y = ciphertexts[i];

    for (size_t candidate_key = 0; candidate_key <= 0xff; candidate_key++) {
      uint8_t l1 = (candidate_key & 0xf0) >> 4;
      uint8_t l2 = candidate_key & 0x0f;

      uint8_t y2 = (y & 0x0f00) >> 8;
      uint8_t y4 = y & 0x000f;

      uint8_t v2 = l1 ^ y2;
      uint8_t v4 = l2 ^ y4;

      uint8_t u2 = PI_S_INV[v2];
      uint8_t u4 = PI_S_INV[v4];

      uint8_t x_5_bit = (x & 0x0800) >> 11;
      uint8_t x_7_bit = (x & 0x0200) >> 9;
      uint8_t x_8_bit = (x & 0x0100) >> 8;
      uint8_t u_6_bit = (u2 & 0x04) >> 2;
      uint8_t u_8_bit = u2 & 0x01;
      uint8_t u_14_bit = (u4 & 0x04) >> 2;
      uint8_t u_16_bit = u4 & 0x01;

      uint8_t z =
        x_5_bit ^ x_7_bit ^ x_8_bit ^ u_6_bit ^ u_8_bit ^ u_14_bit ^ u_16_bit;

      if (z == 0) {
        count[candidate_key]++;
      }
    }
  }

  uint8_t key24 = 0;

  for (size_t i = 0; i <= 0xff; i++) {
    count[i] = (size_t)abs((int)count[i] - (int)size / 2);
    if (count[i] > count[key24]) {
      key24 = i;
    }
  }

  printf("key24: 0x%02x ", key24);

  for (size_t i = 0; i < 8; i++) {
    printf("%d", (key24 & (0x80 >> i)) != 0);
  }
  printf("\n");

  // now continue to the remaining partial keys.
  for (size_t i = 0; i <= 0xff; i++) {
    count[i] = 0;
  }

  uint8_t key2 = (key24 & 0xf0) >> 4;

  for (size_t i = 0; i < size; i++) {
    uint16_t x = plaintexts[i];
    uint16_t y = ciphertexts[i];

    for (size_t candidate_key = 0; candidate_key <= 0xff; candidate_key++) {
      uint8_t l1 = (candidate_key & 0xf0) >> 4;
      uint8_t l2 = candidate_key & 0x0f;

      uint8_t y1 = (y & 0xf000) >> 12;
      uint8_t y2 = (y & 0x0f00) >> 8;
      uint8_t y3 = (y & 0x00f0) >> 4;

      uint8_t v1 = l1 ^ y1;
      uint8_t v2 = key2 ^ y2;
      uint8_t v3 = l2 ^ y3;

      uint8_t u1 = PI_S_INV[v1];
      uint8_t u2 = PI_S_INV[v2];
      uint8_t u3 = PI_S_INV[v3];

      uint8_t x_1_bit = (x & 0x8000) >> 15;
      uint8_t x_2_bit = (x & 0x4000) >> 14;
      uint8_t x_9_bit = (x & 0x0080) >> 7;
      uint8_t x_10_bit = (x & 0x0040) >> 6;
      uint8_t u_4_bit = u1 & 0x01;
      uint8_t u_8_bit = u2 & 0x01;
      uint8_t u_12_bit = u3 & 0x01;

      uint8_t z =
        x_1_bit ^ x_2_bit ^ x_9_bit ^ x_10_bit ^ u_4_bit ^ u_8_bit ^ u_12_bit;

      if (z == 0) {
        count[candidate_key]++;
      }
    }
  }

  uint8_t key13 = 0;

  for (size_t i = 0; i <= 0xff; i++) {
    count[i] = (size_t)abs((int)count[i] - (int)size / 2);
    if (count[i] > count[key13]) {
      key13 = i;
    }
  }

  uint32_t maxkey = 0;

  printf("key13: 0x%02x ", key13);
  for (size_t i = 0; i < 8; i++) {
    printf("%d", (key13 & (0x80 >> i)) != 0);
  }
  printf("\n");

  maxkey = (key13 & 0xf0) << 8 | (key24 & 0xf0) << 4 | (key13 & 0x0f) << 4 |
           (key24 & 0x0f);

  printf("maxkey: 0x%04x ", maxkey);
  for (size_t i = 0; i < 32; i++) {
    printf("%d", (maxkey & (0x80000000 >> i)) != 0);
  }
  printf("\n");

  for (size_t i = 0; i <= 0xff; i++) {
    if (count[i] != count[key13]) {
      continue;
    }
  
    printf("maybe key13: 0x%02x ", (uint8_t)i);

    for (size_t j = 0; j < 8; j++) {
      printf("%d", (i & (0x80 >> j)) != 0);
    }

    printf(" count: %ld\n", count[i]);

    maxkey = ((uint8_t)i & 0xf0) << 8 | (key24 & 0xf0) << 4 |
             ((uint8_t)i & 0x0f) << 4 | (key24 & 0x0f);

    printf("trying key(lo): 0x%04x\n", maxkey);

    for (size_t hi = 0; hi <= 0xffff; hi++) {
      key = hi << 16 | maxkey;

      bool ok = true;

      for (size_t j = 0; j < size; j++) {
        uint16_t x = plaintexts[j];
        uint16_t y = ciphertexts[j];

        if (encrypt(x) != y) {
          ok = false;
          break;
        }
      }

      if (ok) {
        printf("found key: 0x%08x\n", key);
        return key;
      }
    }
  }

  return 0;
}

#define MAX_SIZE 30000

int main(int argc, char* argv[]) {
  if (argc != 2) {
    printf("Usage: %s <data>\n", argv[0]);
    return 1;
  }

  FILE* pair_file = fopen(argv[1], "r");

  uint16_t plaintexts[MAX_SIZE];
  uint16_t ciphertexts[MAX_SIZE];

  size_t size = 0;

  while (fscanf(pair_file, "%hu %hu", &plaintexts[size], &ciphertexts[size]) !=
         EOF) {
    size++;
  }

  fclose(pair_file);

  struct timeval st, ed;

  gettimeofday(&st, NULL);
  uint32_t key = linear_attack(size, plaintexts, ciphertexts);
  gettimeofday(&ed, NULL);

  for (size_t i = 0; i < 32; i++) {
    printf("%d", (key & (0x80000000 >> i)) != 0);
  }

  printf("\n");

  printf(
    "time: %ld us\n",
    (ed.tv_sec - st.tv_sec) * 1000000 + (ed.tv_usec - st.tv_usec)
  );

  return 0;
}