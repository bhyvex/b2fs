/*----- System Includes -----*/

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <pthread.h>

/*----- Local Includes -----*/

#include "../src/structures/stack.h"

/*----- Type Declarations -----*/

typedef struct voidargs {
  int num_operations;
  stack_t *stack;
} voidargs_t;

/*----- Globals -----*/

/*----- Function Declarations -----*/

void *test_stack(void *voidargs);

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
  stack_t *stack = create_stack(free, sizeof(int));
  voidargs_t *args = malloc(sizeof(voidargs_t) * num_threads);
  pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);

  // Start threads.
  for (int i = 0; i < num_threads; i++) {
    args[i] = (voidargs_t) {num_operations, stack};
    pthread_create(&threads[i], NULL, test_stack, &args[i]);
  }

  // Wait for all threads to complete.
  for (int i = 0; i < num_operations / 10; i++) destroy_stack(stack_dup(stack, free));
  for (int i = 0; i < num_threads; i++) pthread_join(threads[i], NULL);

  // Verify contents of stack.
  int holder, counter = 0;
  while (stack_pop(stack, &holder) == STACK_SUCCESS) counter++;
  assert(counter == num_threads * num_operations);

  // Stack works. Clean up and return.
  free(threads);
  free(args);
  destroy_stack(stack);
}

void *test_stack(void *voidargs) {
  voidargs_t *args = voidargs;
  int num_operations = args->num_operations, counter = 0;
  stack_t *stack = args->stack;

  // Push a bunch of stuff onto the stack.
  while (counter++ < num_operations) stack_push(stack, &counter);

  return NULL;
}
