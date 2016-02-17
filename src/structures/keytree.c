/*----- Includes -----*/

#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include "keytree.h"
#include "stack.h"

/*----- Macro Definitions -----*/

#define MAX(a, b) ((a) > (b) ? (a) : (b))

/*----- Type Definitions -----*/

typedef struct tree_node {
  void *key, *value;
  struct tree_node *left, *right, *next, *prev;
  int height;
} tree_node_t;

struct keytree {
  void (*key_destroy) (void *), (*val_destroy) (void *);
  int (*compare) (void *, void *), size, keysize, valsize;
  tree_node_t *root;
  pthread_rwlock_t lock;
};

/*----- Local Function Declarations -----*/

tree_node_t *create_tree_node(void *key, void *value, int keysize, int valsize);
tree_node_t *rotate_right(tree_node_t *subtree);
tree_node_t *rotate_left(tree_node_t *subtree);
int subtree_height(tree_node_t *subtree);
void destroy_tree_node(tree_node_t *node, void (*key_destroy) (void *), void (*val_destroy) (void *));

/*----- Function Implementations -----*/

// KeyTree Functions.

keytree_t *create_keytree(void (*key_destroy) (void *), void (*val_destroy) (void *), int (*compare) (void *, void *), int keysize, int valsize) {
  keytree_t *tree = malloc(sizeof(keytree_t));

  if (tree) {
    tree->key_destroy = key_destroy;
    tree->val_destroy = val_destroy;
    tree->compare = compare;
    tree->size = 0;
    tree->keysize = keysize;
    tree->valsize = valsize;
    tree->root = NULL;
    pthread_rwlock_init(&tree->lock, NULL);
  }

  return tree;
}

int tree_insert(keytree_t *tree, void *key, void *value) {
  if (!tree || !key || !value) return KEYTREE_INVAL;

  // Check if the root node has been set.
  pthread_rwlock_wrlock(&tree->lock);
  if (!tree->root) {
    tree->root = create_tree_node(key, value, tree->keysize, tree->valsize);
    tree->root->next = tree->root;
    tree->root->prev = tree->root;
    pthread_rwlock_unlock(&tree->lock);
    return KEYTREE_SUCCESS;
  }
  pthread_rwlock_unlock(&tree->lock);

  // Create explicit stack and traverse through tree.
  stack_t *stack = create_stack(free, sizeof(tree_node_t *));
  pthread_rwlock_rdlock(&tree->lock);
  tree_node_t *current = tree->root;
  while (current) {
    int comparison = tree->compare(key, current->key);
    
    stack_push(stack, &current);
    if (comparison > 0) {
      // Right child.
      current = current->right;
    } else if (comparison < 0) {
      // Left child.
      current = current->left;
    } else {
      // Duplicate.
      pthread_rwlock_unlock(&tree->lock);
      destroy_stack(stack);
      return KEYTREE_DUPLICATE;
    }
  }

  while (stack_pop(stack, &current) == STACK_SUCCESS) {
    int comparison = tree->compare(key, current->key);

    if (comparison > 0) {
      if (!current->right) current->right = create_tree_node(key, value, tree->keysize, tree->valsize);
      if (subtree_height(current->right) - subtree_height(current->left) == 2) {
        if (tree->compare(key, current->right->key) > 0) {
          rotate_right(current);
        } else {
          current->right = rotate_left(current->right);
          current = rotate_right(current);
        }
      }
    } else if (comparison < 0) {
      if (!current->left) current->left = create_tree_node(key, value, tree->keysize, tree->valsize);
      if (subtree_height(current->left) - subtree_height(current->right) == 2) {
        if (tree->compare(key, current->left->key) > 0) {
          rotate_left(current);
        } else {
          current->left = rotate_right(current->left);
          current->left = rotate_left(current);
        }
      }
    }

    current->height = MAX(subtree_height(current->left), subtree_height(current->right)) + 1;
  }
}

void *tree_find(keytree_t *tree, void *key) {

}

int tree_remove(keytree_t *tree, void *key, void *valbuf) {

}

void tree_destroy(keytree_t *tree) {

}

// Tree Node Functions.

tree_node_t *create_tree_node(void *key, void *value, int keysize, int valsize) {
  tree_node_t *node = calloc(sizeof(tree_node_t), 1);

  if (node) {
    node->key = malloc(keysize);
    node->value = malloc(valsize);
    node->height = 1;
    memcpy(node->key, key, keysize);
    memcpy(node->value, value, valsize);
  }

  return node;
}

tree_node_t *rotate_right(tree_node_t *node) {
  tree_node_t *right_child = node->right;
  node->right = right_child->left;
  right_child->left = node;
  node->height = MAX(subtree_height(node->left), subtree_height(node->right)) + 1;
  right_child->height = MAX(subtree_height(right_child->right), node->height) + 1;
  return right_child;
}

tree_node_t *rotate_left(tree_node_t *node) {
  tree_node_t *left_child = node->left;
  node->left = left_child->right;
  left_child->right = node;
  node->height = MAX(subtree_height(node->left), subtree_height(node->right)) + 1;
  left_child->height = MAX(subtree_height(left_child->left), node->height);
  return left_child;
}

int subtree_height(tree_node_t *node) {
  return node ? node->height : 0;
}

void destroy_tree_node(tree_node_t *node, void (*key_destroy) (void *), void (*val_destroy) (void *)) {
  key_destroy(node->key);
  val_destroy(node->value);
  free(node);
}
