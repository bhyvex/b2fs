/*----- System Includes -----*/

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <pthread.h>

/*----- Local Includes -----*/

#include "../src/structures/array.h"

/*----- Type Declarations -----*/

typedef struct voidargs {
  int num_operations;
  unsigned int seed;
  array_t *array;
} voidargs_t;

/*----- Globals -----*/

long long insertion_count = 0;

/*----- Function Declarations -----*/

void *perform_insertions(void *voidargs);
void decrement_and_destroy(void *voidarg);

/*----- Function Implementations -----*/

int main(int argc, char **argv) {
  int c, index, num_operations = 1024, num_threads = 4;
  struct option long_options[] = {
    {"num-operations", required_argument, 0, 'n'},
    {"num-threads", required_argument, 0, 't'},
    {0, 0, 0, 0}
  };

  // Parse CLI options.
  while ((c = getopt_long(argc, argv, "n:t:", long_options, &index)) != -1) {
    switch (c) {
      case 'n':
        num_operations = atoi(optarg);
        break;
      case 't':
        num_threads = atoi(optarg);
        break;
    }
  }

  // Make necessary allocations.
  array_t *array = create_array(sizeof(int), decrement_and_destroy);
  voidargs_t *args = malloc(sizeof(voidargs_t) * num_threads);
  pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);

  // Usual stuff. Setup arguments and start threads.
  for (int i = 0; i < num_threads; i++) {
    args[i] = (voidargs_t) {num_operations, rand(), array};
    pthread_create(&threads[i], NULL, perform_insertions, &args[i]);
  }
  for (int i = 0; i < num_threads; i++) pthread_join(threads[i], NULL);

  // Validate the array's contents.
  for (int i = 0; i < num_threads * num_operations; i++) {
    int elem;
    if (array_retrieve(array, i, &elem) == ARRAY_SUCCESS) {
      __sync_fetch_and_sub(&insertion_count, elem);
    }
  }

  // Make sure everything was in the array.
  assert(insertion_count == 0);

  // Cleanup.
  array_destroy(array);
  free(args);
  free(threads);

  return EXIT_SUCCESS;
}

void *perform_insertions(void *voidargs) {
  voidargs_t *args = voidargs;

  // Get arguments.
  array_t *array = args->array;
  int num_operations = args->num_operations;
  unsigned int seed = args->seed;

  for (int i = 0; i < num_operations; i++) {
    assert(array_push(array, &i) == ARRAY_SUCCESS);
    __sync_fetch_and_add(&insertion_count, i);
  }

  // Delete a bunch of random entries.
  for (int i = 0; i < num_operations / 2; i++) {
    int slot = rand_r(&seed) % array_count(array);
    array_clear(array, slot);
  }

  return NULL;
}

void decrement_and_destroy(void *voidarg) {
  int value = *(int *) voidarg;
  __sync_fetch_and_sub(&insertion_count, value);
}
