/*----- System Includes -----*/

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/*----- Local Includes -----*/

#include "hash.h"

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
  int count, size, dynamic, frozen;
  pthread_rwlock_t lock;
} hash_t;

/*----- Internal Function Declarations -----*/

hash_node_t *create_hash_node(char *key, void *data);
int insert_hash_node(hash_node_t *head, hash_node_t *insert);
hash_node_t *find_hash_node(hash_node_t *head, char *key);
hash_node_t *remove_hash_node(hash_node_t *head, char *key, void (*destruct) (void *));
void destroy_hash_chain(hash_node_t *head, void (*destruct) (void *));
void destroy_hash_node(hash_node_t *node, void (*destruct) (void *));

/*----- Hash Functions -----*/

int setup_hash(hash_t *table, void (*destruct) (void *)) {
  // Allocate table with calloc to allow for NULL checks.
  int retval = pthread_rwlock_init(&table->lock, NULL);
  table->data = calloc(HASH_START_SIZE, sizeof(hash_node_t *));
  if (table->data && !retval) {
    table->destruct = destruct;
    table->count = 0;
    table->frozen = 0;
    table->size = HASH_START_SIZE;
    return 1;
  }
  return 0;
}

// Function handles creation of a hash struct.
hash_t *create_hash(void (*destruct) (void *)) {
  hash_t *table = malloc(sizeof(hash_t));

  if (table) {
    table->dynamic = 1;
    if (!setup_hash(table, destruct)) {
      free(table);
      table = NULL;
    }
  }

  return table;
}

int init_hash(hash_t *table, void (*destruct) (void *)) {
  if (table && destruct) {
    table->dynamic = 0;
    if (setup_hash(table, destruct)) return HASH_SUCCESS;
    else return HASH_NOMEM;
  }
  return HASH_INVAL;
}

// Function handles creation of a hash value for a given string.
int hash_key(char *key, int size) {
  int proto_hash = 0;
  for (unsigned int i = 0; i < strlen(key); i++) {
    proto_hash += (int) key[i];
  }
  return proto_hash % size;
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
      int hash = hash_key(current->key, table->size * 2);
      if (new_data[hash]) {
        insert_hash_node(new_data[hash], current);
      } else {
        new_data[hash] = current;
      }
      current = tmp;
    }
  }

  // Update hash struct with changes.
  table->data = new_data;
  table->size *= 2;
  free(old_data);

  // Relinquish write-lock.
  pthread_rwlock_unlock(&table->lock);
}

// Insert data into a hash for a specific key.
int hash_put(hash_t *table, char *key, void *data) {
  // Verify parameters.
  if (!table || !key || !data) return HASH_INVAL;

  // Check if table needs a rehash.
  if (table->count / (float) table->size > 0.8) rehash(table);

  // Generate hash value and insert.
  int hash = hash_key(key, table->size);

  // Acquire write lock.
  pthread_rwlock_rdlock(&table->lock);

  // Abort if we're frozen.
  if (table->frozen) {
    pthread_rwlock_unlock(&table->lock);
    return HASH_FROZEN;
  }

  // Verify that table does not already contain given key.
  if (table->data[hash]) {
    // Check if we're dealing with a hash collision, or a repeat key.
    if (!find_hash_node(table->data[hash], key)) {
      // Data is new.
      hash_node_t *node = create_hash_node(key, data);

      // Probably stupid, but taking the read lock first lets us get through the whole function
      // without ever acquiring the write lock if we don't have to rehash and the data already
      // exists.
      pthread_rwlock_unlock(&table->lock);
      pthread_rwlock_wrlock(&table->lock);

      insert_hash_node(table->data[hash], node);
      table->count++;
      pthread_rwlock_unlock(&table->lock);
      return HASH_SUCCESS;
    } else {
      // Key already exists in table.
      pthread_rwlock_unlock(&table->lock);
      return HASH_EXISTS;
    }
  } else {
    hash_node_t *node = create_hash_node(key, data);

    // Probably stupid, but taking the read lock first lets us get through the whole function
    // without ever acquiring the write lock if we don't have to rehash, and the data already
    // exists.
    pthread_rwlock_unlock(&table->lock);
    pthread_rwlock_wrlock(&table->lock);

    // Insert new data into table.
    table->data[hash] = node;
    table->count++;

    pthread_rwlock_unlock(&table->lock);
    return HASH_SUCCESS;
  }
}

// Function handles getting data out of a hash for a specific key.
void *hash_get(hash_t *table, char *key) {
  // Verify parameters.
  if (!table || !table->count || !key) return NULL;

  // Generate hash value.
  int hash = hash_key(key, table->size);

  // Acquire read-lock and find it.
  pthread_rwlock_rdlock(&table->lock);
  hash_node_t *found = find_hash_node(table->data[hash], key);

  if (found) {
    void *data = found->data;
    pthread_rwlock_unlock(&table->lock);
    return data;
  } else {
    pthread_rwlock_unlock(&table->lock);
    return NULL;
  }

}

// Handle removal of a key from hash. Although never actually called in the
// project, it seemed dishonest not to include it.
int hash_drop(hash_t *table, char *key) {
  // Verify parameters.
  if (!table || table->count == 0 || !key) return HASH_INVAL;

  // Generate hash value and find data.
  int hash = hash_key(key, table->size);

  // Acquire read lock for searching.
  pthread_rwlock_rdlock(&table->lock);

  // Abort if we're frozen.
  if (table->frozen) {
    pthread_rwlock_unlock(&table->lock);
    return HASH_FROZEN;
  }

  if (table->data[hash]) {
    if (find_hash_node(table->data[hash], key)) {
      // We found it. Switch locks for writing.
      pthread_rwlock_unlock(&table->lock);
      pthread_rwlock_wrlock(&table->lock);

      // Remove the data.
      table->data[hash] = remove_hash_node(table->data[hash], key, table->destruct);
      table->count--;
      pthread_rwlock_unlock(&table->lock);
      return HASH_SUCCESS;
    } else {
      // Key does not exist in table.
      pthread_rwlock_unlock(&table->lock);
      return HASH_NOTFOUND;
    }
  } else {
    // Key does not exist in table.
    pthread_rwlock_unlock(&table->lock);
    return HASH_NOTFOUND;
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
void destroy_hash(hash_t *table) {
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
  if (table->dynamic) free(table);
}

/*---- Hash Node Functions ----*/

// Function handles the creation of a hash_node struct.
hash_node_t *create_hash_node(char *key, void *data) {
  hash_node_t *node = malloc(sizeof(hash_node_t));

  if (node) {
    // Copy given string so it can't be freed out from under us.
    char *intern_key = (char *) malloc(sizeof(char) * (strlen(key) + 1));
    if (intern_key) {
      strcpy(intern_key, key);
      node->key = intern_key;
      node->data = data;
      node->next = NULL;
    } else {
      // Key could not be copied. Continued initialization impossible.
      free(node);
      node = NULL;
    }
  }

  return node;
}

// Function handles inserting a hash node into a linked list of hash nodes.
int insert_hash_node(hash_node_t *head, hash_node_t *insert) {
  // Validate paramaters and insert if the list doesn't already contain
  // the given node.
  if (head && insert) {
    for (hash_node_t *current = head; current; current = current->next) {
      if (!strcmp(insert->key, current->key)) {
        return 0;
      } else if(!current->next) {
        current->next = insert;
        return 1;
      }
    }
    return 0;
  } else {
    return 0;
  }
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
  destruct(node->data);
  free(node);
}
