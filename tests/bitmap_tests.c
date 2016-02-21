/*----- System Includes -----*/

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <math.h>
#include <pthread.h>

/*----- Local Includes -----*/

#include "../src/structures/bitmap.h"

/*----- Type Declaractions -----*/

typedef struct voidargs {
  bitmap_t *map;
  int *output, map_size, num_threads;
} voidargs_t;

/*----- Function Declarations -----*/

void *make_reservations(void *voidargs);

/*----- Function Implementations -----*/

int main(int argc, char **argv) {
  int c, index, map_size = 1000, num_threads = 4;
  struct option long_options[] = {
    {"num-threads", required_argument, 0, 'n'},
    {"map-size", required_argument, 0, 's'},
    {0, 0, 0, 0}
  };

  while ((c = getopt_long(argc, argv, "n:s:", long_options, &index)) != -1) {
    switch (c) {
      case 'n':
        num_threads = atoi(optarg);
        break;
      case 's':
        map_size = atoi(optarg);
    }
  }

  // Allocate everything we'll need.
  bitmap_t *map = create_bitmap(map_size), *double_check = create_bitmap(map_size);
  int **thread_bits = malloc(sizeof(int *) * num_threads);
  voidargs_t *args = malloc(sizeof(voidargs_t) * num_threads);
  pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);

  // Start up the threads.
  for (int i = 0; i < num_threads; i++) {
    thread_bits[i] = malloc(sizeof(int) * (ceil(map_size / (double) num_threads)));
    memset(thread_bits[i], -1, sizeof(int) * (ceil(map_size / (double) num_threads)));
    args[i] = (voidargs_t) {map, thread_bits[i], map_size, num_threads};
    pthread_create(&threads[i], NULL, make_reservations, &args[i]);
  }

  // Join and validate results.
  for (int i = 0; i < num_threads; i++) {
    pthread_join(threads[i], NULL);
    int *bits = thread_bits[i];

    // Iterate across returned bits, make sure they're all set in the map, and make
    // sure they're also unique.
    for (int j = 0; j < ceil(map_size / (double) num_threads); j++) {
      if (bits[j] != -1) {
        assert(check_bit(map, bits[j]));
        assert(set_bit(double_check, bits[j]) == BITMAP_SUCCESS);
      }
    }
  }

  // Double check that clear_bit is working.
  for (int i = 0; i < map_size; i++) assert(clear_bit(double_check, i) == BITMAP_SUCCESS);

  return EXIT_SUCCESS;
}

void *make_reservations(void *voidargs) {
  voidargs_t *args = voidargs;

  // Get arguments.
  bitmap_t *map = args->map;
  int *output = args->output, map_size = args->map_size, num_threads = args->num_threads;

  // Set bits.
  for (int i = 0; i < map_size / num_threads; i++) output[i] = reserve(map);

  return NULL;
}
