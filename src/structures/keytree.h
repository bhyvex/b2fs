#ifndef B2FS_KEYTREE_H
#define B2FS_KEYTREE_H

/*----- Numerical Constants -----*/

#define KEYTREE_SUCCESS 0x00
#define KEYTREE_INVAL -0x01
#define KEYTREE_DUPLICATE -0x02
#define KEYTREE_NO_SUCH_ELEMENT -0x04

/*----- Type Declarations -----*/

typedef struct keytree keytree_t;

typedef struct keytree_iterator {
  struct keytree_iterator *next, *prev;
} keytree_iterator_t;

/*----- Function Declarations -----*/

keytree_t *create_keytree(void (*key_destroy) (void *), void (*val_destroy) (void *), int (*compare) (void *, void *), int keysize, int valsize);
int keytree_insert(keytree_t *tree, void *key, void *value);
int keytree_find(keytree_t *tree, void *key, void *valbuf);
keytree_iterator_t *keytree_traverse(keytree_t *tree, keytree_iterator_t *it);
int keytree_remove(keytree_t *tree, void *key, void *valbuf);
void keytree_destroy(keytree_t *tree);

#endif
