/*----- System Includes -----*/

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <pthread.h>

/*----- Local Includes -----*/

#include "../src/structures/keytree.h"

/*----- Type Declarations -----*/

typedef struct voidargs {
  int num_operations, strlen, seed;
  keytree_t *tree;
  char **output;
} voidargs_t;

/*----- Globals -----*/

int insertion_count = 0;
char alpha[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h','i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

/*----- Function Declarations -----*/

void *build_tree(void *voidargs);
int keycomp(void *key_one, void *key_two);
void destroy_and_decrement(void *voidarg);

/*----- Function Implementations -----*/

int main(int argc, char **argv) {
  int c, index, num_operations = 1024, num_threads = 4, strlens = 10, double_check = 0;
  struct option long_options[] = {
    {"num-operations", required_argument, 0, 'n'},
    {"string-length", required_argument, 0, 's'},
    {"num-threads", required_argument, 0, 't'},
    {0, 0, 0, 0}
  };

  // Parse CLI options.
  while ((c = getopt_long(argc, argv, "n:s:t:", long_options, &index)) != -1) {
    switch (c) {
      case 'n':
        num_operations = atoi(optarg);
        break;
      case 's':
        strlens = atoi(optarg);
      case 't':
        num_threads = atoi(optarg);
        break;
    }
  }

  // Make necessary allocations.
  keytree_t *tree = create_keytree(free, destroy_and_decrement, keycomp, sizeof(char *), sizeof(char *));
  voidargs_t *args = malloc(sizeof(voidargs_t) * num_threads);
  pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);

  // I'm passing the same arguments to every thread. Wouldn't even need an array of structs.
  // My tests have gotten fomulaic.
  for (int i = 0; i < num_threads; i++) {
    args[i] = (voidargs_t) {num_operations, strlens, rand(), tree, malloc(sizeof(char *) * num_operations)};
    pthread_create(&threads[i], NULL, build_tree, &args[i]);
  }
  for (int i = 0; i < num_threads; i++) pthread_join(threads[i], NULL);

  // Validate the tree's structure.
  keytree_iterator_t *it = keytree_iterate_start(tree, NULL);
  char *keybuf, *valbuf, *oldbuf = NULL, *first = NULL;
  while (double_check++ < num_threads * num_operations) {
    int retval = keytree_iterate_next(it, &keybuf, &valbuf);
    assert(retval == KEYTREE_SUCCESS);
    assert(!strcmp(keybuf, valbuf));
    if (!first) first = keybuf;
    if (oldbuf) assert(strcmp(oldbuf, keybuf) < 0);
    oldbuf = keybuf;
  }
  keytree_iterate_next(it, &keybuf, &valbuf);
  assert(!strcmp(keybuf, first));
  keytree_iterate_stop(it);

  // Destroy tree and verify all destructors fired.
  keytree_destroy(tree);
  assert(!insertion_count);

  // Tree structure is valid. Clean up and return.
  free(args);
  free(threads);
  keytree_destroy(tree);
  return EXIT_SUCCESS;
}

void *build_tree(void *voidargs) {
  voidargs_t *args = voidargs;

  // Get arguments.
  int num_operations = args->num_operations, strlens = args->strlen, seed = args->seed;
  keytree_t *tree = args->tree;
  char **output = args->output;

  for (int i = 0; i < num_operations; i++) {
    // Make room for the string.
    output[i] = malloc(sizeof(char) * (strlens + 1));

    // Generate a unique string to insert.
    while (1) {
      for (int j = 0; j < strlens; j++) output[i][j] = alpha[rand_r(&seed) % 26];
      output[i][strlens] = '\0';

      if (keytree_insert(tree, &output[i], &output[i]) == KEYTREE_SUCCESS) break;
    }

    // Increment the insertion counter.
    __sync_fetch_and_add(&insertion_count, 1);
  }

  return NULL;
}

int keycomp(void *key_one, void *key_two) {
  return strcmp(*(char **) key_one, *(char **) key_two);
}

void destroy_and_decrement(void *voidarg) {
  free(voidarg);
  __sync_fetch_and_sub(&insertion_count, 1);
}
