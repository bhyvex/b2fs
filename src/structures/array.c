/*----- Includes -----*/

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <math.h>
#include "array.h"
#include "bitmap.h"

/*----- Numerical Constants -----*/

#define ARRAY_INIT_LENGTH 8

/*----- Type Definitions -----*/

struct array {
  void *storage;
  bitmap_t *present_map, *lock_map;
  int size, count, elem_size;
  void (*destruct) (void *);
  pthread_rwlock_t realloc_lock;
};

/*----- Array Functions -----*/

// Function is responsible for creating an array struct.
array_t *create_array(int elem_size, void (*destruct) (void *)) {
  array_t *arr = malloc(sizeof(array_t));

  if (arr) {
    // Use calloc to allocate storage space to allow for explicit NULL checks.
    arr->storage = malloc(ARRAY_INIT_LENGTH * elem_size);
    arr->present_map = create_bitmap(ceil(ARRAY_INIT_LENGTH / (float) 8));
    arr->lock_map = create_bitmap(ceil(ARRAY_INIT_LENGTH / (float) 8));
    arr->size = ARRAY_INIT_LENGTH;
    arr->count = 0;
    arr->elem_size = elem_size;
    arr->destruct = destruct;
    pthread_rwlock_init(&arr->realloc_lock, NULL);
  }

  return arr;
}

// Function is responsible for inserting the given data at the specified
// index. If the underlying array is not large enough, apply exponential reallocation
// until it is.
int array_insert(array_t *arr, int index, void *data) {
  // No need to hold lock for this check. Array size increases monotonically, so
  // if the check passes, array is at least large enough for the operation, and
  // if a reallocation is in progress, the insertion will be halted upon attempting
  // to acquire the read-lock.
  if (index >= arr->size) {
    // Acquire the write-lock for reallocation.
    pthread_rwlock_wrlock(&arr->realloc_lock);

    // Someone might have reallocated the array while we were acquiring the lock.
    if (index >= arr->size) {
      // Figure out new size.
      int newsize = 1;
      while (newsize <= index) newsize <<= 1;

      // Reallocate.
      void *tmp = realloc(arr->storage, sizeof(arr->elem_size) * newsize);
      if (tmp) {
        // Memory allocation succeeded.
        arr->storage = tmp;
        arr->size = newsize;
      } else {
        // We're out of memory.
        pthread_rwlock_unlock(&arr->realloc_lock);
        return ARRAY_NOMEM_ERROR;
      }
    }

    // Release write-lock to acquire the read-lock.
    pthread_rwlock_unlock(&arr->realloc_lock);
  }

  // Check to make sure given index is unoccupied.
  pthread_rwlock_rdlock(&arr->realloc_lock);
  if (set_bit(arr->lock_map, index) == BITMAP_SUCCESS) {
    // We are the only one inserting this entry. Copy it over.
    memcpy((char *) arr->storage + (index * arr->elem_size), data, arr->elem_size);

    // Set the corresponding bit so that it can be seen by others.
    set_bit(arr->present_map, index);
    
    // Increase the counter.
    __sync_fetch_and_add(&arr->count, 1);
    pthread_rwlock_unlock(&arr->realloc_lock);
    return ARRAY_SUCCESS;
  } else {
    // Someone else is inserting this entry.
    pthread_rwlock_unlock(&arr->realloc_lock);
    return ARRAY_OCCUPIED_ERROR;
  }
}

int array_push(array_t *arr, void *data) {
  // Array count member is only guarantee eventual consistency, might not be split-second
  // accurate. As such, start at the current array size and keep trying to insert until
  // it succeeds.
  int success = ARRAY_OCCUPIED_ERROR;
  for (int i = arr->count; success != ARRAY_SUCCESS && success != ARRAY_NOMEM_ERROR; i++) success = array_insert(arr, i, data);

  // Could return either ARRAY_SUCCESS or ARRAY_NOMEM_ERROR.
  return success;
}

// Function is responsible for getting the data at a specific index. 
int array_retrieve(array_t *arr, int index, void *buf) {
  pthread_rwlock_rdlock(&arr->realloc_lock);

  // Check if the index is in bounds.
  if (index < arr->size && index >= 0) {
    // The order here is important. The size of the array increases monotonically,
    // so if the previous check passes, we're guaranteed to be working in valid
    // memory. Copy out the value in the slot first, then check if the corresponding
    // present bit is still set. If so, the value we copied must be valid, if not,
    // not.
    memcpy(buf, (char *) arr->storage + (index * arr->elem_size), arr->elem_size);
    if (check_bit(arr->present_map, index)) {
      pthread_rwlock_unlock(&arr->realloc_lock);
      return ARRAY_SUCCESS;
    } else {
      // Doesn't exist.
      pthread_rwlock_unlock(&arr->realloc_lock);
      return ARRAY_UNOCCUPIED_ERROR;
    }
  } else {
    // Doesn't exist.
    pthread_rwlock_unlock(&arr->realloc_lock);
    return ARRAY_UNOCCUPIED_ERROR;
  }
}

// Function empties a specific index and returns the contained data.
int array_clear(array_t *arr, int index) {
  pthread_rwlock_rdlock(&arr->realloc_lock);

  // If this passes, we are the only one removing this, insertions cannot occur
  // for this slot yet as the lock bit is still set, and any retrievals won't see
  // it. If not, not.
  if (clear_bit(arr->present_map, index) == BITMAP_SUCCESS) {
    // Copy value out so the user can't screw up something in our address space.
    void *voidbuf = malloc(arr->elem_size);
    memcpy(voidbuf, (char *) arr->storage + (index * arr->elem_size), arr->elem_size);
    arr->destruct(voidbuf);
    free(voidbuf);

    // Clear the insert lock so the slot can be used again.
    clear_bit(arr->lock_map, index);

    // Decrement, unlock, and return.
    __sync_fetch_and_sub(&arr->count, 1);
    pthread_rwlock_unlock(&arr->realloc_lock);
    return ARRAY_SUCCESS;
  } else {
    pthread_rwlock_unlock(&arr->realloc_lock);
    return ARRAY_UNOCCUPIED_ERROR;
  }
}

// Function is responsible for destroying an array struct and all associated
// data.
void array_destroy(array_t *arr) {
  // Acquire the write-lock to ensure nobody is using this array.
  pthread_rwlock_wrlock(&arr->realloc_lock);

  // Iterate across the array and destroy everything in it.
  void *voidbuf = malloc(arr->elem_size);
  for (int i = 0; i < arr->size; i++) {
    if (clear_bit(arr->present_map, i) == BITMAP_SUCCESS) {
      // Entry exists in the array. Get rid of it. Once again, copy it out.
      memcpy(voidbuf, (char *) arr->storage + i, arr->elem_size);
      arr->destruct(voidbuf);

      // This wouldn't be strictly necessary since we're eventually going to destroy
      // the array, but oh well.
      clear_bit(arr->lock_map, i);
    }
  }
  free(voidbuf);

  // Clear up allocated members of the array.
  free(arr->storage);
  destroy_bitmap(arr->present_map);
  destroy_bitmap(arr->lock_map);

  // We've cleaned up everything but the lock. If somebody is blocked on this, bad
  // news for them.
  pthread_rwlock_destroy(&arr->realloc_lock);
  
  // Finish up.
  free(arr);
}

int array_count(array_t *arr) {
  return arr->count;
}
