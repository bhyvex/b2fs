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

typedef struct list {
  list_node_t *head, *tail;
  int count, dynamic, frozen, elem_len;
  pthread_mutex_t mutex;
  void (*destruct) (void *);
} list_t;

/*----- Internal Function Declarations -----*/

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

int init_list(list_t *lst, int elem_len, void (*destruct) (void *)) {
  if (lst) {
    lst->dynamic = 0;
    if (setup_list(lst, elem_len, destruct)) return LIST_SUCCESS;
    else return LIST_NOMEM;
  }
  return LIST_INVAL;
}

int lpush(list_t *lst, void *data) {
  // Validate given parameters.
  if (!lst || !data) return LIST_INVAL;

  list_node_t *node = create_list_node(data, lst->elem_len);
  if (node) {
    pthread_mutex_lock(&lst->mutex);

    // Push data into list at head and increment count.
    if (lst->head) {
      node->next = lst->head;
      lst->head->prev = node;
      lst->head = node;
    } else {
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

  pthread_mutex_lock(&lst->mutex);

  // Pop data off the end of the queue and decrement count.
  list_node_t *node = lst->tail;
  if (lst->count > 1) {
    lst->tail = lst->tail->prev;
    lst->tail->next = NULL;
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
