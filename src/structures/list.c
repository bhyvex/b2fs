/*----- Includes -----*/

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "list.h"

/*----- Numerical Constants -----*/

#define LIST_WAIT_BASE 1000000

/*----- Type Definitions -----*/

typedef struct list_node {
  void *data;
  int references;
  struct list_node *next, *prev;
} list_node_t;

struct list {
  list_node_t *head, *tail;
  int count, frozen, elem_len;
  pthread_rwlock_t lock;
  void (*destruct) (void *);
};

struct list_iterator {
  list_node_t *next;
  pthread_rwlock_t *lock;
  int elem_len, reverse;
};

/*----- Internal Function Declarations -----*/

int intern_push(list_t *lst, void *data, int left);
int intern_pop(list_t *lst, void *buf, int left);

list_node_t *create_list_node(void *data, int elem_len);
void destroy_list_node(list_node_t *node, pthread_rwlock_t *lock, void (*destruct) (void *));

/*----- List Functions -----*/

// Function is responsible for creating a list struct.
list_t *create_list(int elem_len, void (*destruct) (void *)) {
  list_t *lst = malloc(sizeof(list_t));

  if (lst) {
    lst->head = NULL;
    lst->tail = NULL;
    lst->count = 0;
    lst->frozen = 0;
    lst->elem_len = elem_len;
    lst->destruct = destruct;
    if (pthread_rwlock_init(&lst->lock, NULL)) {
      free(lst);
      lst = NULL;
    }
  }

  return lst;
}

int lpush(list_t *lst, void *data) {
  if (!lst || !data) return LIST_INVAL;
  return intern_push(lst, data, 1);
}

int rpush(list_t *lst, void *data) {
  if (!lst || !data) return LIST_INVAL;
  return intern_push(lst, data, 0);
}

int intern_push(list_t *lst, void *data, int left) {
  list_node_t *node = create_list_node(data, lst->elem_len);

  if (node) {
    pthread_rwlock_wrlock(&lst->lock);

    if (lst->head && left) {
      // Push data into list at head.
      node->next = lst->head;
      lst->head->prev = node;
      lst->head = node;
    } else if (lst->head) {
      // Push data into list at tail.
      lst->tail->next = node;
      node->prev = lst->tail;
      lst->tail = node;
    } else {
      // Push into list.
      lst->head = node;
      lst->tail = node;
    }
    lst->count++;

    pthread_rwlock_unlock(&lst->lock);
    return LIST_SUCCESS;
  }

  return LIST_NOMEM;
}

int rpop(list_t *lst, void *buf) {
  // Validate given parameters.
  if (!lst || !buf) return LIST_INVAL;

  pthread_rwlock_rdlock(&lst->lock);
  if (!lst->count) {
    pthread_rwlock_unlock(&lst->lock);
    return LIST_EMPTY;
  }
  return intern_pop(lst, buf, 0);
}

int lpop(list_t *lst, void *buf) {
  if (!lst || !buf) return LIST_INVAL;

  pthread_rwlock_rdlock(&lst->lock);
  if (!lst->count) {
    pthread_rwlock_unlock(&lst->lock);
    return LIST_EMPTY;
  }
  return intern_pop(lst, buf, 1);
}

// Function takes care of actual popping work.
int intern_pop(list_t *lst, void *buf, int left) {
  // Function is called with read-lock held.
  // Since you can't upgrade a read-lock to a write lock atomically, we need to
  // recheck that there is still an item to dequeue after acquiring the write-lock.
  pthread_rwlock_unlock(&lst->lock);
  pthread_rwlock_wrlock(&lst->lock);
  if (!lst->count) {
    pthread_rwlock_unlock(&lst->lock);
    return LIST_EMPTY;
  }

  // Pop data off the end of the queue and decrement count.
  list_node_t *node = left ? lst->head : lst->tail;
  if (lst->count > 1) {
    if (left) {
      lst->head = lst->head->next;
      lst->head->prev = NULL;
    } else {
      lst->tail = lst->tail->prev;
      lst->tail->next = NULL;
    }
  } else {
    lst->head = NULL;
    lst->tail = NULL;
  }
  lst->count--;

  // Isolate the data, destroy the node, and return.
  memcpy(buf, node->data, lst->elem_len);
  destroy_list_node(node, &lst->lock, lst->destruct);
  pthread_rwlock_unlock(&lst->lock);
  return LIST_SUCCESS;
}

int lhead(list_t *lst, void *buf) {
  if (!lst) return LIST_INVAL;

  pthread_rwlock_rdlock(&lst->lock);
  if (!lst->head) {
    pthread_rwlock_unlock(&lst->lock);
    return LIST_EMPTY;
  }
  void *data = lst->head->data;
  memcpy(buf, data, lst->elem_len);
  pthread_rwlock_unlock(&lst->lock);

  return LIST_SUCCESS;
}

int ltail(list_t *lst, void *buf) {
  if (!lst) return LIST_INVAL;

  pthread_rwlock_rdlock(&lst->lock);
  if (!lst->tail) {
    pthread_rwlock_unlock(&lst->lock);
    return LIST_EMPTY;
  }
  void *data = lst->head->data;
  memcpy(buf, data, lst->elem_len);
  pthread_rwlock_unlock(&lst->lock);

  return LIST_SUCCESS;
}

list_iterator_t *literate_start(list_t *lst, int reverse) {
  if (!lst) return NULL;

  list_iterator_t *it = malloc(sizeof(list_iterator_t));
  pthread_rwlock_rdlock(&lst->lock);
  if (it) {
    // Assign pointers.
    it->next = reverse ? lst->tail : lst->head;

    // Increment references for entire list.
    list_node_t *curr = it->next;
    while (curr) {
      __sync_fetch_and_add(&curr->references, 1);
      curr = reverse ? curr->prev : curr->next;
    }
    it->elem_len = lst->elem_len;
    it->lock = &lst->lock;
    it->reverse = reverse;
  }
  pthread_rwlock_unlock(&lst->lock);

  return it;
}

// FIXME: Seeing as the destruction functions honor reference counts, and insertions
// and deletions can only occur at list ends, this could most likely be implemented
// without acquiring a read-lock.
int literate_next(list_iterator_t *it, void *voidbuf) {
  if (!it) return LIST_INVAL;

  if (it->next) {
    pthread_rwlock_rdlock(it->lock);
    list_node_t *next = it->next;
    memcpy(voidbuf, next->data, it->elem_len);
    it->next = it->reverse ? next->prev : next->next;

    // Iterations only travel in one direction, so decrement the reference count for
    // the node we're moving off of.
    __sync_fetch_and_sub(&next->references, 1);
    pthread_rwlock_unlock(it->lock);
    return LIST_SUCCESS;
  }

  return LIST_EMPTY;
}

void literate_stop(list_iterator_t *it) {
  if (!it) return;

  // Decrement any remaining references.
  list_node_t *curr = it->next;
  while (curr) {
    __sync_fetch_and_sub(&curr->references, 1);
    curr = it->reverse ? curr->prev : curr->next;
  }
  free(it);
}

int lelem_len(list_t *lst) {
  return lst->elem_len;
}

// Function is responsible for destroying a list.
void destroy_list(list_t *lst) {
  if (!lst) return;

  // If list contains data, iterate across it, freeing nodes as we go.
  pthread_rwlock_wrlock(&lst->lock);
  if (lst->count) {
    list_node_t *current = lst->head;
    while (current) {
      list_node_t *tmp = current;
      current = current->next;
      destroy_list_node(tmp, &lst->lock, lst->destruct);
    }
  }
  pthread_rwlock_unlock(&lst->lock);

  // Release the list's mutex.
  pthread_rwlock_destroy(&lst->lock);

  // Free list if necessary.
  free(lst);
}

/*----- List Node Functions -----*/

// Function is responsible for creating a list node struct.
list_node_t *create_list_node(void *data, int elem_len) {
  list_node_t *node = malloc(sizeof(list_node_t));

  if (node) {
    node->data = malloc(elem_len);
    if (node->data) {
      memcpy(node->data, data, elem_len);
      node->references = 0;
      node->next = NULL;
      node->prev = NULL;
    } else {
      free(node->data);
      free(node);
      node = NULL;
    }
  } else {
    free(node);
    node = NULL;
  }

  return node;
}

// Function is responsible for destroying a list node.
// Blocks until all references to the node have been forfeited, expects to be called
// with the write-lock held, and does not release it.
void destroy_list_node(list_node_t *node, pthread_rwlock_t *lock, void (*destruct) (void *)) {
  struct timespec ts;
  for (int i = 0; node->references; i++) {
    pthread_rwlock_unlock(lock);
    if (i > 10) i = 10;

    int factor = 1 << i;
    unsigned long long total_wait = LIST_WAIT_BASE * factor;
    ts.tv_sec = total_wait / 1000000000;
    ts.tv_nsec = total_wait % 1000000000;
    nanosleep(&ts, NULL);
    pthread_rwlock_wrlock(lock);
  }
  destruct(node->data);
  free(node->data);
  free(node);
}
