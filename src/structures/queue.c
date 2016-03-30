/*----- Includes -----*/

#include <stdlib.h>
#include "queue.h"
#include "list.h"

/*----- Type Definitions -----*/

struct queue {
  list_t *lst;
};

/*----- Function Implementations -----*/

queue_t *create_queue(void (*destruct) (void *), int elem_len) {
  queue_t *queue = malloc(sizeof(queue_t));

  if (queue) queue->lst = create_list(elem_len, destruct);
  if (!queue->lst) {
    free(queue);
    queue = NULL;
  }

  return queue;
}

void queue_enqueue(queue_t *queue, void *data) {
  if (!queue || !data) return;
  lpush(queue->lst, data);
}

int queue_dequeue(queue_t *queue, void *buf) {
  if (!queue || !buf) return QUEUE_INVAL;
  if (rpop(queue->lst, buf) == LIST_EMPTY) return QUEUE_EMPTY;
  else return QUEUE_SUCCESS;
}

int queue_peek(queue_t *queue, void *buf) {
  if (!queue || !buf) return QUEUE_INVAL;
  if (ltail(queue->lst, buf) == LIST_EMPTY) return QUEUE_EMPTY;
  else return QUEUE_SUCCESS;
}

queue_t *queue_dup(queue_t *queue, void (*destruct) (void *)) {
  queue_t *dup = create_queue(destruct, lelem_len(queue->lst));
  char *voidbuf = malloc(lelem_len(queue->lst));

  list_iterator_t *it = literate_start(queue->lst, 0);
  while (literate_next(it, voidbuf) == LIST_SUCCESS) rpush(dup->lst, voidbuf);
  literate_stop(it);

  free(voidbuf);
  return dup;
}

void destroy_queue(queue_t *queue) {
  destroy_list(queue->lst);
  free(queue);
}
