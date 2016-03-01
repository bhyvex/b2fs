#ifndef B2FS_ARRAY_H
#define B2FS_ARRAY_H

/*----- Numerical Constants -----*/

#define ARRAY_SUCCESS 0x00
#define ARRAY_NOMEM_ERROR -0x01
#define ARRAY_OCCUPIED_ERROR -0x02
#define ARRAY_UNOCCUPIED_ERROR -0x04

/*----- Struct Declarations -----*/

typedef struct array array_t;

/*----- Array Functions -----*/

array_t *create_array(int elem_size, void (*destruct) (void *));
int array_insert(array_t *arr, int index, void *data);
int array_push(array_t *arr, void *data);
int array_retrieve(array_t *arr, int index, void *buf);
int array_clear(array_t *arr, int index);
void array_destroy(array_t *arr);

int array_count(array_t *arr);

#endif
