/*----- Includes -----*/

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <limits.h>
#include "bitmap.h"

/*----- Numerical Constants -----*/

#define BITMAP_DEFAULT_SIZE 8

/*----- Type Definitions -----*/

struct bitmap {
  char *map;
  int size, occupied;
  pthread_rwlock_t lock;
};

/*----- Local Function Definitions -----*/

int reallocate(bitmap_t *map, int size);

/*----- Function Implementations -----*/

bitmap_t *create_bitmap(int size) {
  bitmap_t *bits = malloc(sizeof(bitmap_t));

  if (bits) {
    memset(bits, 0, sizeof(bitmap_t));
    bits->map = calloc(size ? sizeof(char) * size : sizeof(char) * BITMAP_DEFAULT_SIZE, 1);
    bits->size = size;
    pthread_rwlock_init(&bits->lock, NULL);
  }

  return bits;
}

int set_bit(bitmap_t *bits, int bit) {
  int byte = bit / 8, byte_bit = bit % 8;
  if (byte >= bits->size) reallocate(bits, byte);

  // Acquire read lock to allow for reallocations.
  pthread_rwlock_rdlock(&bits->lock);

  // Atomically update.
  char value = __sync_fetch_and_or(&bits->map[byte], (char) 1 << byte_bit);
  if (value & 1 << byte_bit) {
    pthread_rwlock_unlock(&bits->lock);
    return BITMAP_OCCUPIED_ERROR;
  } else {
    __sync_fetch_and_add(&bits->occupied, 1);
    pthread_rwlock_unlock(&bits->lock);
    return BITMAP_SUCCESS;
  }
}

int clear_bit(bitmap_t *bits, int bit) {
  int byte = bit / 8, byte_bit = bit % 8;
  if (byte >= bits->size) reallocate(bits, byte);

  // Acquire read-lock to allow for reallocations
  pthread_rwlock_rdlock(&bits->lock);

  // Atomically update.
  char value = __sync_fetch_and_and(&bits->map[byte], (char) ~(1 << byte_bit));
  if (value & 1 << byte_bit) {
    __sync_fetch_and_sub(&bits->occupied, 1);
    pthread_rwlock_unlock(&bits->lock);
    return BITMAP_SUCCESS;
  } else {
    pthread_rwlock_unlock(&bits->lock);
    return BITMAP_VACANT_ERROR;
  }
}

int check_bit(bitmap_t *bits, int bit) {
  int byte = bit / 8, byte_bit = bit % 8;
  if (byte >= bits->size) reallocate(bits, byte);

  // Acquire read-lock to allow for reallocations
  pthread_rwlock_rdlock(&bits->lock);

  int val = bits->map[byte] & 1 << byte_bit;
  pthread_rwlock_unlock(&bits->lock);
  return val;
}

int reserve(bitmap_t *bits) {
  // Iterate until we find an open slot, or we overflow.
  for (unsigned int index = 0; index < UINT_MAX; index++) {
    if (set_bit(bits, index) == BITMAP_SUCCESS) {
      pthread_rwlock_unlock(&bits->lock);
      return index;
    }
  }

  return BITMAP_FULL_ERROR;
}

void destroy_bitmap(bitmap_t *bits) {
  pthread_rwlock_destroy(&bits->lock);
  free(bits->map);
  free(bits);
}

int reallocate(bitmap_t *map, int size) {
  pthread_rwlock_wrlock(&map->lock);

  // Now that we're holding the write-lock, double check things.
  if (map->size > size) {
    // We were called multiple times, job is already done. Return.
    pthread_rwlock_unlock(&map->lock);
    return BITMAP_SUCCESS;
  }

  // Figure out the next allocation size.
  int powers = 1;
  while (powers <= size) powers <<= 1;

  // Perform reallocation.
  void *tmp = realloc(map->map, sizeof(char) * powers);
  if (!tmp) return BITMAP_NOMEM_ERROR;
  memset((char *) tmp + map->size, 0, powers - map->size);
  map->map = tmp;
  map->size = powers;

  pthread_rwlock_unlock(&map->lock);

  return BITMAP_SUCCESS;
}
