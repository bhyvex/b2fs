#ifndef B2FS_LIST_H
#define B2FS_LIST_H

/*----- Numerical Constants -----*/

#define LIST_SUCCESS 0x00
#define LIST_FROZEN -0x01
#define LIST_NOMEM -0x02
#define LIST_INVAL -0x04
#define LIST_EMPTY -0x08

/*----- Type Declarations -----*/

typedef struct list list_t;
typedef struct list_iterator list_iterator_t;

/*----- Function Declarations -----*/

// List Creator and Destructor.
list_t *create_list(int elem_len, void (*destruct) (void *));
void destroy_list(list_t *lst);

// List Manipulation Functions.
int lpush(list_t *lst, void *data);
int rpush(list_t *lst, void *data);
int lpop(list_t *lst, void *buf);
int rpop(list_t *lst, void *buf);
void *lhead(list_t *lst);
void *ltail(list_t *lst);

// List Iterator Functions.
list_iterator_t *literate_start(list_t *lst);
int literate_next(list_iterator_t *it, void *voidbuf);
int literate_prev(list_iterator_t *it, void *voidbuf);
void literate_stop(list_iterator_t *it);

// Helper Functions.
int lelem_len(list_t *lst);

#endif
