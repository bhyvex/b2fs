/*----- Includes -----*/

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "list.h"

/*----- Type Definitions -----*/

typedef struct list_node {
  void *data;
  struct list_node *next, *prev;
} list_node_t;

// FIXME: Need to update these files. Use of a generic mutex is wasteful in this
// instance. Should use a pthread_rwlock_t;
struct list {
  list_node_t *head, *tail;
  int count, dynamic, frozen, elem_len;
  pthread_mutex_t mutex;
  void (*destruct) (void *);
};

struct list_iterator {
  list_node_t *next, *prev;
  pthread_mutex_t *lock;
  int elem_len;
};

/*----- Internal Function Declarations -----*/

int intern_push(list_t *lst, void *data, int left);
int intern_pop(list_t *lst, void *buf, int left);

list_node_t *create_list_node(void *data, int elem_len);
void destroy_list_node(list_node_t *node, void (*destruct) (void *));

/*----- List Functions -----*/

int setup_list(list_t *lst, int elem_len, void (*destruct) (void *)) {
  int retval = pthread_mutex_init(&lst->mutex, NULL);
  if (!retval) {
    lst->head = NULL;
    lst->tail = NULL;
    lst->count = 0;
    lst->frozen = 0;
    lst->elem_len = elem_len;
    lst->destruct = destruct;
    return 1;
  }
  return 0;
}

// Function is responsible for creating a list struct.
list_t *create_list(int elem_len, void (*destruct) (void *)) {
  list_t *lst = malloc(sizeof(list_t));

  if (lst) {
    lst->dynamic = 1;
    if (!setup_list(lst, elem_len, destruct)) {
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
    pthread_mutex_lock(&lst->mutex);

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

    pthread_mutex_unlock(&lst->mutex);
    return LIST_SUCCESS;
  }

  return LIST_NOMEM;
}

int rpop(list_t *lst, void *buf) {
  // Validate given parameters.
  if (!lst || !buf) return LIST_INVAL;
  if (!lst->count) return LIST_EMPTY;
  return intern_pop(lst, buf, 0);
}

int lpop(list_t *lst, void *buf) {
  if (!lst || !buf) return LIST_INVAL;
  if (!lst->count) return  LIST_EMPTY;
  return intern_pop(lst, buf, 1);
}

int intern_pop(list_t *lst, void *buf, int left) {
  pthread_mutex_lock(&lst->mutex);

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

  pthread_mutex_unlock(&lst->mutex);

  // Isolate the data, destroy the node, and return.
  memcpy(buf, node->data, lst->elem_len);
  destroy_list_node(node, lst->destruct);
  return LIST_SUCCESS;
}

void *lhead(list_t *lst) {
  if (!lst) return NULL;
  else if (!lst->head) return NULL;
  return lst->head->data;
}

void *ltail(list_t *lst) {
  if (!lst) return NULL;
  else if (!lst->tail) return NULL;
  return lst->tail->data;
}

list_iterator_t *literate_start(list_t *lst) {
  if (!lst) return NULL;

  list_iterator_t *it = malloc(sizeof(list_iterator_t));
  pthread_mutex_lock(&lst->mutex);
  if (it) {
    it->next = lst->head;
    it->prev = NULL;
    it->elem_len = lst->elem_len;
    it->lock = &lst->mutex;
  }
  pthread_mutex_unlock(&lst->mutex);

  return it;
}

// FIXME: This function is naive. It's possible for the node it's iterating
// across to be removed from the list and freed. Need to resolve this eventually.
int literate_next(list_iterator_t *it, void *voidbuf) {
  if (!it) return LIST_INVAL;

  pthread_mutex_lock(it->lock);
  if (it->next) {
    list_node_t *next = it->next;
    memcpy(voidbuf, next->data, it->elem_len);
    it->next = next->next;
    it->prev = next->prev;
    pthread_mutex_unlock(it->lock);
    return LIST_SUCCESS;
  } else {
    pthread_mutex_unlock(it->lock);
    return LIST_EMPTY;
  }
}

// FIXME: This function is naive. It's possible for the node it's iterating
// across to be removed from the list and freed. Need to resolve this eventually.
int literate_prev(list_iterator_t *it, void *voidbuf) {
  if (!it) return LIST_INVAL;

  pthread_mutex_lock(it->lock);
  if (it->prev) {
    list_node_t *prev = it->prev;
    memcpy(voidbuf, prev->data, it->elem_len);
    it->next = prev->next;
    it->prev = prev->prev;
    pthread_mutex_unlock(it->lock);
    return LIST_SUCCESS;
  } else {
    pthread_mutex_unlock(it->lock);
    return LIST_EMPTY;
  }
}

void literate_stop(list_iterator_t *it) {
  free(it);
}

int lelem_len(list_t *lst) {
  return lst->elem_len;
}

// Function is responsible for destroying a list.
void destroy_list(list_t *lst) {
  if (!lst) return;

  // If list contains data, iterate across it, freeing nodes as we go.
  if (lst->count) {
    list_node_t *current = lst->head;
    while (current) {
      list_node_t *tmp = current;
      current = current->next;
      destroy_list_node(tmp, lst->destruct);
    }
  }

  // Release the list's mutex.
  pthread_mutex_destroy(&lst->mutex);

  // Free list if necessary.
  if (lst->dynamic) free(lst);
}

/*----- List Node Functions -----*/

// Function is responsible for creating a list node struct.
list_node_t *create_list_node(void *data, int elem_len) {
  list_node_t *node = malloc(sizeof(list_node_t));
  void *data_cpy = malloc(elem_len);

  if (node && data_cpy) {
    node->data = data_cpy;
    memcpy(node->data, data, elem_len);
    node->next = NULL;
    node->prev = NULL;
  } else if (!data_cpy) {
    free(node);
    node = NULL;
  } else {
    free(data_cpy);
  }

  return node;
}

// Function is responsible for destroying a list node.
void destroy_list_node(list_node_t *node, void (*destruct) (void *)) {
  destruct(node->data);
  free(node);
}
