/*----- System Includes -----*/

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <pthread.h>

/*----- Local Includes -----*/

#include "../src/structures/list.h"

/*----- Type Declarations -----*/

typedef struct voidargs {
  list_t *list;
  int num_operations;
} voidargs_t;

/*----- Globals -----*/

int enqueue_count = 0, dequeue_count = 0, list_total = 0;
int destruct_count = 0;

/*----- Function Declarations -----*/

void *enqueue(void *voidargs);
void *dequeue(void *voidargs);
void destruct(void *voidarg);

/*----- Function Implementations -----*/

int main(int argc, char **argv) {
  int c, index, num_threads = 4, num_operations = 1024;
  struct option long_options[] = {
    {"num-operations", required_argument, 0, 'n'},
    {"num-threads", required_argument, 0 , 't'},
    {0, 0, 0, 0}
  };

  // Get CLI options.
  while ((c = getopt_long(argc, argv, "n:t:", long_options, &index)) != -1) {
    switch (c) {
      case 'n':
        num_operations = atoi(optarg);
        break;
      case 't':
        num_threads = atoi(optarg);
    }
  }

  // Make necessary allocations.
  list_t *list = create_list(sizeof(int), destruct);
  voidargs_t *args = malloc(sizeof(voidargs_t) * num_threads);
  pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);
  int prod_count = 0, cons_count = 0;

  // Start the threads working.
  for (int i = 0; i < num_threads; i++) {
    args[i] = (voidargs_t) {list, num_operations};
    void *(*operation) (void *);
    if (i % 2 == 0) {
      operation = enqueue;
      prod_count++;
    } else {
      operation = dequeue;
      cons_count++;
    }
    pthread_create(&threads[i], NULL, operation, &args[i]);
  }

  // Wait for everyone to finish.
  for (int i = 0; i < num_threads; i++) pthread_join(threads[i], NULL);

  // Check final state.
  assert(list_total == 0);
  assert(enqueue_count == (num_operations + prod_count));
  assert(dequeue_count == (num_operations + cons_count));
  assert(destruct_count == num_operations);

  // List works. Clean up and return.
  destroy_list(list);
  free(args);
  free(threads);

  return EXIT_SUCCESS;
}

void *enqueue(void *voidargs) {
  voidargs_t *args = voidargs;

  // Get arguments.
  list_t *list = args->list;
  int num_operations = args->num_operations, current;

  while ((current = __sync_fetch_and_add(&enqueue_count, 1)) < num_operations) {
    assert(lpush(list, &current) == LIST_SUCCESS);
    __sync_fetch_and_add(&list_total, current);
  }

  return NULL;
}

void *dequeue(void *voidargs) {
  voidargs_t *args = voidargs;

  // Get arguments.
  list_t *list = args->list;
  int num_operations = args->num_operations, current;

  while (__sync_fetch_and_add(&dequeue_count, 1) < num_operations) {
    int retval = LIST_EMPTY;
    while (retval != LIST_SUCCESS) retval = rpop(list, &current);
    __sync_fetch_and_sub(&list_total, current);
  }

  return NULL;
}

void destruct(void *voidarg) {
  free(voidarg);
  __sync_fetch_and_add(&destruct_count, 1);
}
