#ifndef B2FS_ARRAY_H
#define B2FS_ARRAY_H

/*----- Numerical Constants -----*/

#define ARRAY_SUCCESS 0x00
#define ARRAY_NOMEM -0x01
#define ARRAY_OCCUPIED -0x02

/*----- Struct Declarations -----*/

typedef struct array array_t;

/*----- Array Functions -----*/

array_t *create_array();
int insert(array_t *arr, int index, void *data);
int push(array_t *arr, void *data);
void *retrieve(array_t *arr, int index);
void *clear(array_t *arr, int index);
void destroy_array(array_t *arr, void (*destruct) (void *));

#endif
