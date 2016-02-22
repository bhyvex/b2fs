/*----- System Includes -----*/

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <math.h>
#include <pthread.h>

/*----- Local Includes -----*/

#include "../src/structures/hash.h"

/*----- Type Declarations -----*/

typedef struct voidargs {
  hash_t *hash;
  char **output;
  int num_insertions, strlen;
  unsigned int seed;
} voidargs_t;

/*----- Globals -----*/

int insertion_count = 0;
char alpha[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h','i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

/*----- Function Declarations -----*/

void *perform_insertions(void *voidargs);
void destroy_and_decrement(void *voidarg);

/*----- Function Implementations -----*/

int main(int argc, char **argv) {
  int c, index, num_threads = 4, num_insertions = 1024, strlen = 10;
  struct option long_options[] = {
    {"num-insertions", required_argument, 0, 'n'},
    {"string-length", required_argument, 0, 's'},
    {"num-threads", required_argument, 0, 't'},
    {0, 0, 0, 0}
  };

  // Get CLI options.
  while ((c = getopt_long(argc, argv, "n:s:t:", long_options, &index)) != -1) {
    switch (c) {
      case 'n':
        num_insertions = atoi(optarg);
        break;
      case 's':
        strlen = atoi(optarg);
        break;
      case 't':
        num_threads = atoi(optarg);
    }
  }

  // Make necessary allocations.
  hash_t *hash = create_hash(destroy_and_decrement);
  char ***thread_keys = malloc(sizeof(char **) * num_threads);
  voidargs_t *args = malloc(sizeof(voidargs_t) * num_threads);
  pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);

  // Start the threads working.
  for (int i = 0; i < num_threads; i++) {
    thread_keys[i] = calloc(sizeof(char **), num_insertions);
    args[i] = (voidargs_t) {hash, thread_keys[i], num_insertions, strlen, rand()};
    pthread_create(&threads[i], NULL, perform_insertions, &args[i]);
  }

  // Check all of the insertions.
  for (int i = 0; i < num_threads; i++) {
    pthread_join(threads[i], NULL);

    char **keys = thread_keys[i];
    for (int j = 0; j < num_insertions; j++) {
      char *key = keys[j], *value = hash_get(hash, key);
      assert(!strcmp(key, value));
      assert(hash_drop(hash, key) == HASH_SUCCESS);
    }
  }

  // Check that all destructors fire.
  destroy_hash(hash);
  assert(!insertion_count);

  // Hash works. Clean up and return.
  for (int i = 0; i < num_threads; i++) free(thread_keys[i]);
  free(thread_keys);
  free(args);
  free(threads);
  return EXIT_SUCCESS;
}

void *perform_insertions(void *voidargs) {
  voidargs_t *args = voidargs;

  // Get arguments.
  hash_t *hash = args->hash;
  char **output = args->output;
  int num_insertions = args->num_insertions, strlen = args->strlen;
  unsigned int seed = args->seed;

  for (int i = 0; i < num_insertions; i++) {
    // Allocate space for string.
    output[i] = malloc(sizeof(char) * (strlen + 1));

    // Generate string and ensure uniqueness.
    while (1) {
      for (int j = 0; j < strlen; j++) output[i][j] = alpha[rand_r(&seed) % 26];
      output[i][strlen] = '\0';

      // Insert it into the hash.
      if (hash_put(hash, output[i], output[i]) == HASH_SUCCESS) break;
    }

    // Increment the insertion counter.
    __sync_fetch_and_add(&insertion_count, 1);
  }

  return NULL;
}

void destroy_and_decrement(void *voidarg) {
  free(voidarg);
  __sync_fetch_and_sub(&insertion_count, 1);
}
