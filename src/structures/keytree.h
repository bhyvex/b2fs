#ifndef B2FS_KEYTREE_H
#define B2FS_KEYTREE_H

/*----- Numerical Constants -----*/

#define KEYTREE_SUCCESS 0x00
#define KEYTREE_INVAL -0x01
#define KEYTREE_DUPLICATE -0x02

/*----- Type Declarations -----*/

typedef struct keytree keytree_t;

typedef struct keytree_iterator {
  struct keytree_iterator *next, *prev;
} keytree_iterator_t;

/*----- Function Declarations -----*/

keytree_t *create_keytree(void (*key_destroy) (void *), void (*val_destroy) (void *), int (*compare) (void *, void *), int keysize, int valsize);
int tree_insert(keytree_t *tree, void *key, void *value);
void *tree_find(keytree_t *tree, void *key);
keytree_iterator_t *tree_traverse(keytree_t *tree, keytree_iterator_t *it);
int tree_remove(keytree_t *tree, void *key, void *valbuf);
void tree_destroy(keytree_t *tree);

#endif
