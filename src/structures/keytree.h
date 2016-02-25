#ifndef B2FS_KEYTREE_H
#define B2FS_KEYTREE_H

/*----- Numerical Constants -----*/

#define KEYTREE_SUCCESS 0x00
#define KEYTREE_INVAL -0x01
#define KEYTREE_DUPLICATE -0x02
#define KEYTREE_NO_SUCH_ELEMENT -0x04

/*----- Type Declarations -----*/

typedef struct keytree keytree_t;

typedef struct keytree_iterator keytree_iterator_t;

/*----- Function Declarations -----*/

// KeyTree creation and destruction functions.
keytree_t *create_keytree(void (*key_destroy) (void *), void (*val_destroy) (void *), int (*compare) (void *, void *), int keysize, int valsize);
void keytree_destroy(keytree_t *tree);

// KeyTree mutation functions.
int keytree_insert(keytree_t *tree, void *key, void *value);
int keytree_find(keytree_t *tree, void *key, void *valbuf);
int keytree_remove(keytree_t *tree, void *key, void *valbuf);

// KeyTree iteration functions.
keytree_iterator_t *keytree_iterate_start(keytree_t *tree, void *target_key);
int keytree_iterate_next(keytree_iterator_t *it, void *keybuf, void *valbuf);
int keytree_iterate_prev(keytree_iterator_t *it, void *keybuf, void *valbuf);
void keytree_iterate_stop(keytree_iterator_t *it);

void print_keytree(keytree_t *tree);

#endif
