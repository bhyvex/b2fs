#ifndef B2FS_STACK_H
#define B2FS_STACK_H

/*----- Numerical Constants -----*/

#define STACK_SUCCESS 0x00
#define STACK_INVAL -0x01
#define STACK_EMPTY -0x02

/*----- Type Declarations -----*/

typedef struct stack stack_t;

/*----- Function Declaractions -----*/

stack_t *create_stack(void (*destruct) (void *), int elem_len);
void stack_push(stack_t *stack, void *data);
int stack_pop(stack_t *stack, void *buf);
int stack_peek(stack_t *stack, void *buf);
stack_t *stack_dup(stack_t *stack, void (*destruct) (void *));
void destroy_stack(stack_t *stack);

#endif
