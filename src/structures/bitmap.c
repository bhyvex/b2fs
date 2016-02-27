/*----- Includes -----*/

#include <stdlib.h>
#include <string.h>
#include "bitmap.h"

/*----- Type Definitions -----*/

struct bitmap {
  int size;
  char *map;
};

/*----- Function Implementations -----*/

bitmap_t *create_bitmap(int size) {
  bitmap_t *bits = malloc(sizeof(bitmap_t));

  if (bits) {
    memset(bits, 0, sizeof(bitmap_t));
    bits->map = calloc(sizeof(char) * size, 1);
    bits->size = size;
  }

  return bits;
}

int set_bit(bitmap_t *bits, int bit) {
  int byte = bit / 8, byte_bit = bit % 8;
  if (byte > bits->size) return BITMAP_RANGE_ERROR;

  // Atomically update.
  char value = __sync_fetch_and_or(&bits->map[byte], (char) 1 << byte_bit);
  if (value & 1 << byte_bit) return BITMAP_OCCUPIED_ERROR;
  else return BITMAP_SUCCESS;
}

int clear_bit(bitmap_t *bits, int bit) {
  int byte = bit / 8, byte_bit = bit % 8;
  if (byte > bits->size) return BITMAP_RANGE_ERROR;

  // Atomically update.
  char value = __sync_fetch_and_and(&bits->map[byte], (char) ~(1 << byte_bit));
  if (value & 1 << byte_bit) return BITMAP_SUCCESS;
  else return BITMAP_VACANT_ERROR;
}

// FIXME: Not convinced this function is actually very useful.
int check_bit(bitmap_t *bits, int bit) {
  int byte = bit / 8, byte_bit = bit % 8;
  if (byte > bits->size) return BITMAP_RANGE_ERROR;
  return bits->map[byte] & 1 << byte_bit;
}

int reserve(bitmap_t *bits) {
  int found = 0, broken = 0;
  for (int byte = 0; byte < bits->size; byte++) {
    for (int bit = 0; bit < 8; bit++) {
      char value = __sync_fetch_and_or(&bits->map[byte], (char) 1 << bit);
      if (!(value & 1 << bit)) {
        found = (8 * byte) + bit;
        broken = 1;
        break;
      }
    }
    if (broken) break;
  }
  return broken ? found : BITMAP_FULL_ERROR;
}

void destroy_bitmap(bitmap_t *bits) {
  free(bits->map);
  free(bits);
}
