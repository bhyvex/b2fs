/*----- Includes -----*/

#include <stdlib.h>
#include <string.h>
#include "array.h"
#include "bitmap.h"

/*----- Numerical Constants -----*/

#define ARRAY_INIT_LENGTH 8

/*----- Type Definitions -----*/

struct array {
    void *storage;
    bitmap_t *map;
    int size, count, elem_size;
    void (*destruct) (void *);
};

/*----- Array Functions -----*/

// Function is responsible for creating an array struct.
array_t *create_array(void (*destruct) (void *)) {
  array_t *arr = malloc(sizeof(array_t));

  if (arr) {
    // Use calloc to allocate storage space to allow for explicit NULL checks.
    arr->storage = malloc(ARRAY_INIT_LENGTH * sizeof(void **));
    arr->map = create_bitmap(ARRAY_INIT_LENGTH);
    arr->size = ARRAY_INIT_LENGTH;
    arr->count = 0;;
  }

  return arr;
}

// Function is responsible for inserting the given data at the specified
// index. If the underlying array is not large enough, apply exponential reallocation
// until it is.
int insert(array_t *arr, int index, void *data) {
  // Check that array is large enough.
  while (index >= arr->size) {
    // Reallocate array.
    int start_size = arr->size;
    arr->size *= 2;
    void **temp = (void **) realloc(arr->storage, sizeof(void *) * arr->size);
    if (temp) {
      // Allocation succeeded. Initialize all new memory to zero to allow for
      // explicit NULL checks.
      memset(&temp[start_size], 0, (arr->size - start_size) * sizeof(void *));
      arr->storage = temp;
    } else {
      // We are out of memory, and the insertion is impossible.
      return ARRAY_NOMEM;
    }
  }

  // Check to make sure given index is unoccupied.
  if (!arr->storage[index]) {
    arr->storage[index] = data;
    arr->count++;
    return ARRAY_SUCCESS;
  } else {
    // Index is occupied. Abort insertion.
    return ARRAY_OCCUPIED;
  }
}

int push(array_t *arr, void *data) {
  return insert(arr, arr->count, data);
}

// Function is responsible for getting the data at a specific index. Invalid
// indexes return NULL.
void *retrieve(array_t *arr, int index) {
  if (index < arr->size && index >= 0) {
    return arr->storage[index];
  } else {
    return NULL;
  }
}

// Function empties a specific index and returns the contained data.
void *clear(array_t *arr, int index) {
  if (index < arr->size) {
    void *temp = arr->storage[index];
    arr->storage[index] = NULL;
    arr->count--;
    return temp;
  } else {
    return NULL;
  }
}

// Function is responsible for destroying an array struct and all associated
// data.
void destroy_array(array_t *arr, void (*destruct) (void *)) {
  for (int i = 0; i < arr->size; i++) {
    if (arr->storage[i]) {
      destruct(arr->storage[i]);
    }
  }

  free(arr);
}
