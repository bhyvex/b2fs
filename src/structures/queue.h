#ifndef B2FS_QUEUE_H
#define B2FS_QUEUE_H

/*----- Numerical Constants -----*/

#define QUEUE_SUCCESS 0x00
#define QUEUE_INVAL -0x01
#define QUEUE_EMPTY -0x02

/*----- Type Declarations -----*/

typedef struct queue queue_t;

/*----- Function Declarations -----*/

queue_t *create_queue(void (*destruct) (void *), int elem_len);
void queue_enqueue(queue_t *queue, void *data);
int queue_dequeue(queue_t *queue, void *buf);
int queue_peek(queue_t *queue, void *buf);
queue_t *queue_dup(queue_t *queue, void (*destruct) (void *));
void destroy_queue(queue_t *queue);

#endif
