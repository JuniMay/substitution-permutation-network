#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "sys/time.h"

/// Inverse substitution parameters
const uint8_t PI_S_INV[16] = {0xE, 0x3, 0x4, 0x8, 0x1, 0xC, 0xA, 0xF,
                              0x7, 0xD, 0x9, 0x6, 0xB, 0x2, 0x0, 0x5};

/// Linear attack
uint8_t
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

  uint8_t maxkey = 0;

  for (size_t i = 0; i <= 0xff; i++) {
    count[i] = (size_t)abs((int)count[i] - (int)size / 2);
    if (count[i] > count[maxkey]) {
      maxkey = i;
    }
  }

  return maxkey;
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
  uint8_t key = linear_attack(size, plaintexts, ciphertexts);
  gettimeofday(&ed, NULL);

  for (size_t i = 0; i < 8; i++) {
    printf("%d", (key & (0x80 >> i)) != 0);
  }

  printf("\n");

  printf(
    "time: %ld us\n",
    (ed.tv_sec - st.tv_sec) * 1000000 + (ed.tv_usec - st.tv_usec)
  );

  return 0;
}