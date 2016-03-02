/*----- Includes -----*/

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "hash.h"
#include "../xxhash/xxhash.h"

/*----- Numerical Constants -----*/

#define HASH_START_SIZE 10

/*----- Type Definitions -----*/

// Node struct used for chaining hash collision resolution.
typedef struct hash_node {
  char *key;
  void *data;
  struct hash_node *next;
} hash_node_t;

typedef struct hash {
  hash_node_t **data;
  void (*destruct) (void *);
  int count, size, frozen, elem_size;
  pthread_rwlock_t lock;
} hash_t;

/*----- Internal Function Declarations -----*/

hash_node_t *create_hash_node(char *key, void *data, int elem_size);
hash_node_t *insert_hash_node(hash_node_t *head, hash_node_t *insert);
hash_node_t *find_hash_node(hash_node_t *head, char *key);
hash_node_t *remove_hash_node(hash_node_t *head, char *key, void (*destruct) (void *));
void destroy_hash_chain(hash_node_t *head, void (*destruct) (void *));
void destroy_hash_node(hash_node_t *node, void (*destruct) (void *));

/*----- Hash Functions -----*/

// Function handles creation of a hash struct.
hash_t *create_hash(int elem_size, void (*destruct) (void *)) {
  hash_t *table = malloc(sizeof(hash_t));

  if (table) {
    int retval = pthread_rwlock_init(&table->lock, NULL);
    table->data = calloc(HASH_START_SIZE, sizeof(hash_node_t *));
    if (table->data && !retval) {
      table->destruct = destruct;
      table->count = 0;
      table->size = HASH_START_SIZE;
      table->frozen = 0;
      table->elem_size = elem_size;
    } else {
      // Initialization of a member variable failed.
      if (table->data) free(table->data);
      if (!retval) pthread_rwlock_destroy(&table->lock);
      free(table);
      table = NULL;
    }
  }

  return table;
}

// Function handles the rehash process encountered when a hash reaches
// 80% capacity. Hate locking the entire function, but we're rehashing, so it's
// pretty much unavoidable.
void rehash(hash_t *table) {
  // Acquire write-lock for hash.
  pthread_rwlock_wrlock(&table->lock);

  // Abort rehash if we're frozen.
  if (table->frozen) {
    pthread_rwlock_unlock(&table->lock);
    return;
  }

  // Allocate new table with calloc to allow for NULL checks.
  hash_node_t **new_data = calloc(table->size * 2, sizeof(hash_node_t *));

  // Copy all previous data into new, larger, hash.
  hash_node_t **old_data = table->data;
  for(int i = 0; i < table->size; i++) {
    hash_node_t *current = old_data[i];
    while (current) {
      hash_node_t *tmp = current->next;
      current->next = NULL;

      // Calculate new hash value and insert.
      unsigned int hash = (unsigned int) XXH64(current->key, strlen(current->key), 0) % (table->size * 2);
      new_data[hash] = insert_hash_node(new_data[hash], current);
      current = tmp;
    }
  }

  // Update hash struct with changes.
  table->data = new_data;
  table->size *= 2;
  free(old_data);
}

// Insert data into a hash for a specific key.
int hash_put(hash_t *table, char *key, void *data) {
  // Verify parameters.
  if (!table || !key || !data) return HASH_INVAL_ERROR;

  // Check if table needs a rehash.
  int rehashed = 0;
  if (table->count / (float) table->size > 0.8) {
    rehash(table);
    rehashed = 1;
  }

  // Acquire read lock if we didn't rehash the table.
  if (!rehashed) pthread_rwlock_rdlock(&table->lock);

  // Cache the table size so that we can detect rehashes in the future.
  int orig_size = table->size;

  // Generate hash value and insert.
  unsigned int hash = (unsigned int) XXH64(key, strlen(key), 0) % table->size;

  // Abort if we're frozen.
  if (table->frozen) {
    pthread_rwlock_unlock(&table->lock);
    return HASH_FROZEN_ERROR;
  }

  // Verify that table does not already contain given key.
  // Check if we're dealing with a hash collision, or a repeat key.
  if (!find_hash_node(table->data[hash], key)) {
    // If we didn't need to rehash the table, grab the write-lock now.
    // If we didn't rehash, means that we've gotten to this point with only a read-lock.
    // Possible for two threads to attempt to insert the same key at the same time and
    // both make it here. After acquiring the write-lock, double check that the key
    // doesn't exist in the list.
    if (!rehashed) {
      pthread_rwlock_unlock(&table->lock);
      pthread_rwlock_wrlock(&table->lock);

      // It's possible, since read-locks can't be converted to write-locks atomically,
      // that someone rehashed the table while we were unlocked. Update the hash value
      // if this happened.
      if (table->size != orig_size) hash = (unsigned int) XXH64(key, strlen(key), 0) % table->size;

      // Recheck for the key.
      if (find_hash_node(table->data[hash], key)) {
        // Contention on duplicate key insert.
        pthread_rwlock_unlock(&table->lock);
        return HASH_EXISTS_ERROR;
      }
    }

    // Data is new.
    hash_node_t *node = create_hash_node(key, data, table->elem_size);

    // We have exclusive write access to the hash, and are the only thread attempting to insert this
    // key. Do the deed.
    table->data[hash] = insert_hash_node(table->data[hash], node);
    table->count++;
    pthread_rwlock_unlock(&table->lock);
    return HASH_SUCCESS;
  } else {
    // Key already exists in table.
    pthread_rwlock_unlock(&table->lock);
    return HASH_EXISTS_ERROR;
  }
}

// Function handles getting data out of a hash for a specific key.
int hash_get(hash_t *table, char *key, void *buf) {
  // Verify parameters.
  if (!table || !table->count || !key || !buf) return HASH_INVAL_ERROR;

  // Acquire read-lock.
  pthread_rwlock_rdlock(&table->lock);

  // Generate hash value.
  unsigned int hash = (unsigned int) XXH64(key, strlen(key), 0) % table->size;

  // Find it.
  hash_node_t *found = find_hash_node(table->data[hash], key);

  // Return the data if it was found.
  if (found) {
    memcpy(buf, found->data, table->elem_size);
    pthread_rwlock_unlock(&table->lock);
    return HASH_SUCCESS;
  } else {
    return HASH_NOTFOUND_ERROR;
  }
}

// Handle removal of a key from hash.
int hash_drop(hash_t *table, char *key) {
  // Verify parameters.
  if (!table || table->count == 0 || !key) return HASH_INVAL_ERROR;

  // Acquire read lock for searching.
  pthread_rwlock_rdlock(&table->lock);

  // Generate hash value and find data.
  unsigned int hash = (unsigned int) XXH64(key, strlen(key), 0) % table->size;

  // Abort if we're frozen.
  if (table->frozen) {
    pthread_rwlock_unlock(&table->lock);
    return HASH_FROZEN_ERROR;
  }

  if (find_hash_node(table->data[hash], key)) {
    // We found it. Switch locks for writing.
    // Since we've only used a read-lock up to this point, it's possible for
    // multiple threads to attempt to delete the same key and all make it to this
    // point. Ensure that we're the first one here, and the only one to do the work
    // by checking for the key again.
    pthread_rwlock_unlock(&table->lock);
    pthread_rwlock_wrlock(&table->lock);
    if (!find_hash_node(table->data[hash], key)) {
      // Contention on key removal.
      pthread_rwlock_unlock(&table->lock);
      return HASH_NOTFOUND_ERROR;
    }

    // We have exclusive write access to the hash, and have verified that we're
    // either the first, or the only, thread trying to delete this key.
    table->data[hash] = remove_hash_node(table->data[hash], key, table->destruct);
    table->count--;
    pthread_rwlock_unlock(&table->lock);
    return HASH_SUCCESS;
  } else {
    // Key does not exist in table.
    pthread_rwlock_unlock(&table->lock);
    return HASH_NOTFOUND_ERROR;
  }
}

// Function handles the enumeration of all keys currently stored in hash.
// Returns said keys in any order.
char **hash_keys(hash_t *table) {
  if (!table) return NULL;

  // Allocate key array.
  int current = 0;
  char **keys = (char **) malloc(sizeof(char *) * table->count);

  // Iterate across each array index, and each hash_node chain.
  pthread_rwlock_rdlock(&table->lock);
  for (int i = 0; i < table->size; i++) {
    if (table->data[i]) {
      for (hash_node_t *tmp = table->data[i]; tmp; tmp = tmp->next) {
        keys[current] = tmp->key;
        current++;
      }
    }
  }
  pthread_rwlock_unlock(&table->lock);

  return keys;
}

void hash_freeze(hash_t *table) {
  if (!table) return;

  pthread_rwlock_wrlock(&table->lock);
  table->frozen = 1;
  pthread_rwlock_unlock(&table->lock);
}

// Function handles the destruction of hash struct.
void hash_destroy(hash_t *table) {
  // Verify parameters.
  if (!table) return;

  // Get the write lock, just in case some poor soul is still trying to read data out.
  pthread_rwlock_wrlock(&table->lock);
  if (table->count > 0) {
    // Destroy all necessary data.
    for (int i = 0; i < table->size; i++) {
      hash_node_t *node = table->data[i];
      if (node) destroy_hash_chain(node, table->destruct);
    }
  }
  free(table->data);

  // Finish the job.
  pthread_rwlock_unlock(&table->lock);
  pthread_rwlock_destroy(&table->lock);
  free(table);
}

/*---- Hash Node Functions ----*/

// Function handles the creation of a hash_node struct.
hash_node_t *create_hash_node(char *key, void *data, int elem_size) {
  hash_node_t *node = malloc(sizeof(hash_node_t));

  if (node) {
    // Copy given string so it can't be freed out from under us.
    node->key = malloc(sizeof(char) * (strlen(key) + 1));
    node->data = malloc(elem_size);
    if (node->key && node->data) {
      strcpy(node->key, key);
      memcpy(node->data, data, elem_size);
      node->next = NULL;
    } else {
      // Key could not be copied. Continued initialization impossible.
      if (node->key) free(node->key);
      if (node->data) free(node->data);
      free(node);
      node = NULL;
    }
  }

  return node;
}

// Function handles inserting a hash node into a linked list of hash nodes.
hash_node_t *insert_hash_node(hash_node_t *head, hash_node_t *insert) {
  // Validate paramaters and insert if the list doesn't already contain
  // the given node.
  if (head && insert) {
    for (hash_node_t *current = head; current; current = current->next) {
      if (!strcmp(insert->key, current->key)) {
        return head;
      } else if(!current->next) {
        current->next = insert;
        return head;
      }
    }
    return 0;
  } else if (insert) {
    return insert;
  }
  return head;
}

// Function handles finding hash_node with a specific key in a linked list
// of nodes.
hash_node_t *find_hash_node(hash_node_t *head, char *key) {
  // Validate parameters and search.
  if (head && key) {
    for (hash_node_t *current = head; current; current = current->next) {
      if (!strcmp(current->key, key)) {
        // Found it.
        return current;
      }
    }

    // Didn't find it.
    return NULL;
  } else {
    return NULL;
  }
}

// Function handles removing a hash_node specified by key from a linked
// list of nodes.
hash_node_t *remove_hash_node(hash_node_t *head, char *key, void (*destruct) (void *)) {
  // Validate parameters and search.
  if (head && key && destruct) {
    hash_node_t *prev = NULL;
    for (hash_node_t *current = head; current; current = current->next) {
      if (!strcmp(current->key, key)) {
        // Found it.
        if (prev) {
          // Normal case.
          hash_node_t *tmp = current->next;
          destroy_hash_node(current, destruct);
          prev->next = tmp;
          return head;
        } else {
          // We need to remove the head.
          destroy_hash_node(head, destruct);
          return head->next;
        }
      }
      prev = current;
    }
  }
  return head;
}

// Function handles the destruction of an entire linked list of hash_nodes.
void destroy_hash_chain(hash_node_t *head, void (*destruct) (void *)) {
  // Iterate across list and destroy each node we come to.
  while (head) {
    hash_node_t *tmp = head;
    head = head->next;
    destroy_hash_node(tmp, destruct);
  }
}

// Function handles the destruction of a specific hash_node struct.
void destroy_hash_node(hash_node_t *node, void (*destruct) (void *)) {
  free(node->key);
  if (destruct) destruct(node->data);
  free(node->data);
  free(node);
}
