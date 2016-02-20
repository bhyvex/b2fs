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

/*----- Function Declarations -----*/

list_t *create_list(int elem_len, void (*destruct) (void *));
int lpush(list_t *lst, void *data);
int rpush(list_t *lst, void *data);
int lpop(list_t *lst, void *buf);
int rpop(list_t *lst, void *buf);
void *lhead(list_t *lst);
void *ltail(list_t *lst);
void destroy_list(list_t *lst);

#endif
