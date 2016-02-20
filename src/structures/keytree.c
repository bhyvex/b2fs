/*----- Includes -----*/

#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include "keytree.h"
#include "stack.h"

/*----- Macro Definitions -----*/

#define MAX(a, b) ((a) > (b) ? (a) : (b))

/*----- Numerical Constants -----*/

#define KEYTREE_WAIT_BASE 1000000

/*----- Type Definitions -----*/

typedef struct tree_node {
  void *key, *value;
  struct tree_node *left, *right, *next, *prev;
  int height, references;
} tree_node_t;

struct keytree {
  void (*key_destroy) (void *), (*val_destroy) (void *);
  int (*compare) (void *, void *), size, keysize, valsize;
  tree_node_t *root;
  pthread_rwlock_t lock;
};

/*----- Local Function Declarations -----*/

stack_t *internal_traverse(keytree_t *tree, void *key, int acquire);
tree_node_t *rotate_right(tree_node_t *subtree);
tree_node_t *rotate_left(tree_node_t *subtree);
int subtree_height(tree_node_t *subtree);
tree_node_t *create_tree_node(void *key, void *value, int keysize, int valsize);
void dereference_and_destroy(void *voidarg);
void destroy_tree_node(tree_node_t *node, pthread_rwlock_t *lock, void (*key_destroy) (void *), void (*val_destroy) (void *));

/*----- Function Implementations -----*/

// KeyTree Functions.

// Function creates a KeyTree, obviously.
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

// Function takes care of inserting a key-value pair into the tree.
int keytree_insert(keytree_t *tree, void *key, void *value) {
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

  // Spin and traverse until we lock the insertion point.
  stack_t *stack;
  tree_node_t *current;
  while (1) {
    // Traverse to find insertion point.
    // Note that the read-lock is no longer held when this returns.
    stack = internal_traverse(tree, key, 1);

    // Attempt to lock insertion point.
    pthread_rwlock_wrlock(&tree->lock);
    tree_node_t *parent = stack_peek(stack), *child = NULL;
    if (tree->compare(key, parent->key) > 0) {
      child = parent->right;
    } else if (tree->compare(key, parent->key) < 0) {
      child = parent->left;
    } else {
      // Duplicate.
      pthread_rwlock_unlock(&tree->lock);
      return KEYTREE_DUPLICATE;
    }
    if (!child) break;

    // Someone else already inserted here. Try again...
    pthread_rwlock_unlock(&tree->lock);
    destroy_stack(stack);
  }

  // We've found and own our insertion point. Perform the insertion, rebalance the tree, and unlock.
  while (stack_pop(stack, &current) == STACK_SUCCESS) {
    if (tree->compare(key, current->key) > 0) {
      if (!current->right) current->right = create_tree_node(key, value, tree->keysize, tree->valsize);
      if (subtree_height(current->right) - subtree_height(current->left) == 2) {
        if (tree->compare(key, current->right->key) > 0) {
          rotate_right(current);
        } else {
          current->right = rotate_left(current->right);
          current = rotate_right(current);
        }
      }
    } else {
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

    // We're about to pop this node off the stack, so decrease the reference count.
    __sync_fetch_and_sub(&current->references, 1);
  }
  pthread_rwlock_unlock(&tree->lock);
  destroy_stack(stack);

  return KEYTREE_SUCCESS;
}

// Function takes care of retrieving a key-value pair from the tree.
int keytree_find(keytree_t *tree, void *key, void *valbuf) {
  if (!tree || !key) return KEYTREE_INVAL;

  // Perform traversal to find given key.
  int success = 0;
  stack_t *stack = internal_traverse(tree, key, 1);

  // FIXME: I do not believe that we need to hold the read lock for the following
  // comparison line. The only functions that can mutate the tree are keytree_insert,
  // and keytree_remove, and while they could reorganize the tree on us, we've
  // already found our node, and we still hold a reference to it, so it can't be freed
  // yet, and keytree_insert doesn't mutate in place.
  if (!tree->compare(((tree_node_t *) stack_peek(stack))->key, key)) {
    // This is the node we're looking for.
    tree_node_t *target = stack_peek(stack);
    memcpy(valbuf, target->value, tree->valsize);
    success = 1;
  }
  pthread_rwlock_unlock(&tree->lock);
  destroy_stack(stack);

  return success ? KEYTREE_SUCCESS : KEYTREE_NO_SUCH_ELEMENT;
}

// Function takes care of removing a key-value pair from the tree.
// If other threads are referencing the node we want to delete, function blocks
// until they release their references.
int keytree_remove(keytree_t *tree, void *key, void *valbuf) {
  if (!tree || !key) return KEYTREE_INVAL;

  // Traverse tree to find the element we want to remove.
  stack_t *stack = internal_traverse(tree, key, 1);

  // FIXME: I do not believe that we need to hold the read lock for this line for
  // the same reasons outlined in the previous function. We acquire the write lock
  // on the following line, and if the tree is mutated in the intervening time, it
  // was either by keytree_insert, or us. If it was keytree_insert, the tree will
  // have been reorganized, but we only care about the structure of the tree while
  // holding the write lock. If it's mutated by us, we'll perform a double check
  // to make sure the node still exists.
  if (!tree->compare(((tree_node_t *) stack_peek(stack))->key, key)) {
    tree_node_t *removed;

    // Forfeit our reference to the deleted node, acquire write lock, and attempt
    // to find the node in the tree again.
    // If there is contention, and there are multiple threads trying to delete
    // this node simulatenously, we are either the leader or a follower in this
    // operation.
    // If we are the leader, we will find the node in the tree on the second go,
    // we will remove it from the tree, and we will wait for the references to hit
    // zero to free the node.
    // If we are a follower, we will not find the node in the tree, and will give up.
    // We must forfeit our reference before acquiring the write lock as otherwise
    // multiple deleters could deadlock.
    // If there are other readers in the tree, holding a reference to the node, the
    // leader will wait until they have exited the tree to free the node.
    stack_pop(stack, &removed);
    pthread_rwlock_wrlock(&tree->lock);

    // Note that we do not acquire a write lock for this traversal.
    stack_t *second_stack = internal_traverse(tree, key, 0);
    if (!tree->compare(((tree_node_t *) stack_peek(second_stack))->key, key)) {
      // We are the leader!
      destroy_stack(second_stack);

      // Remove and rebalance if necessary.
      tree_node_t *parent;
      stack_pop(stack, &parent);
      int comparison = tree->compare(parent->key, key);
      if (!removed->left && !removed->right) {
        // Easy life. Node has no children.
        if (comparison > 0) parent->right = NULL;
        else parent->left = NULL;
      } else if (removed->right && !removed->left) {
        // Still ok. Need to reassign a child, but no need to rebalance.
        if (comparison > 0) parent->right = removed->right;
        else parent->left = removed->right;
      } else if (removed->left && !removed->right) {
        // Still ok. Need to reassign a child, but no need to rebalance.
        if (comparison > 0) parent->right = removed->left;
        else parent->left = removed->left;
      } else {
        // Dammit. Two children. Need to rebalance.
        // TODO: This.
      }

      // Destroy the node.
      destroy_tree_node(removed, &tree->lock, tree->key_destroy, tree->val_destroy);
      return KEYTREE_SUCCESS;
    } else {
      // We are a follower...
      // Nothing left to do. Leave removal up to leader (may already be done).
      destroy_stack(second_stack);
      return KEYTREE_SUCCESS;
    }
  } else {
    pthread_rwlock_unlock(&tree->lock);
    destroy_stack(stack);
    return KEYTREE_NO_SUCH_ELEMENT;
  }
}

// Function destroys a KeyTree, obviously.
void keytree_destroy(keytree_t *tree) {

}

// Tree helper functions.

stack_t *internal_traverse(keytree_t *tree, void *key, int acquire) {
  stack_t *stack = create_stack(dereference_and_destroy, sizeof(tree_node_t *));

  // Lock the tree for reading and perform traversal.
  if (acquire) pthread_rwlock_rdlock(&tree->lock);
  tree_node_t *current = tree->root;
  while (current) {
    int comparison = tree->compare(key, current->key);
    
    // We're pushing this node onto the stack, so increase the reference count.
    __sync_fetch_and_add(&current->references, 1);
    stack_push(stack, &current);
    if (comparison > 0) {
      // Right child.
      current = current->right;
    } else if (comparison < 0) {
      // Left child.
      current = current->left;
    } else {
      // Duplicate.
      break;
    }
  }
  if (acquire) pthread_rwlock_unlock(&tree->lock);

  return stack;
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

void dereference_and_destroy(void *voidarg) {
  tree_node_t **node_ptr = voidarg;
  __sync_fetch_and_sub(&((*node_ptr)->references), 1);
  free(node_ptr);
}

// Function takes care of destroying a tree node.
// Function blocks until node references hit 0.
// Function expects wrlock to be held when called.
void destroy_tree_node(tree_node_t *node, pthread_rwlock_t *lock, void (*key_destroy) (void *), void (*val_destroy) (void *)) {
  struct timespec ts;
  for (int i = 0; node->references; i++) {
    pthread_rwlock_unlock(lock);
    if (i > 10) i = 10;

    // Figure out how long to sleep for.
    int factor = 1 << i;
    unsigned long long total_wait = KEYTREE_WAIT_BASE * factor;
    ts.tv_sec = total_wait / 1000000000;
    ts.tv_nsec = total_wait % 1000000000;
    nanosleep(&ts, NULL);
    pthread_rwlock_wrlock(lock);
  }

  // References are now 0. Destroy the node while we can.
  key_destroy(node->key);
  val_destroy(node->value);
  free(node);

  // We're done. Unlock and return.
  pthread_rwlock_unlock(lock);
}
