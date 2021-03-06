#ifndef B2FS_HASH_H
#define B2FS_HASH_H

/*----- Numerical Constants -----*/

#define HASH_SUCCESS 0x00
#define HASH_FROZEN_ERROR -0x01
#define HASH_NOMEM_ERROR -0x02
#define HASH_INVAL_ERROR -0x04
#define HASH_EXISTS_ERROR -0x08
#define HASH_NOTFOUND_ERROR -0x10

/*----- Type Declarations -----*/

typedef struct hash hash_t;

/*----- Hash Functions -----*/

hash_t *create_hash(int elem_size, void (*destruct) (void *));
int hash_put(hash_t *table, char *key, void *data);
int hash_get(hash_t *table, char *key, void *buf);
int hash_drop(hash_t *table, char *key);
int hash_count(hash_t *table);
char **hash_keys(hash_t *table, int *count);
void hash_freeze(hash_t *table);
void hash_destroy(hash_t *table);

#endif
