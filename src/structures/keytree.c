/*----- Includes -----*/

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include "keytree.h"
#include "stack.h"
#include "list.h"

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

struct keytree_iterator {
  pthread_rwlock_t *lock;
  tree_node_t *curr;
  int keysize, valsize;
};

struct keytree {
  void (*key_destroy) (void *), (*val_destroy) (void *);
  int (*compare) (void *, void *), size, keysize, valsize;
  tree_node_t *root;
  pthread_rwlock_t lock;
};

/*----- Local Function Declarations -----*/

stack_t *internal_traverse(keytree_t *tree, void *key, int acquire);
tree_node_t *balance(tree_node_t *subtree);
tree_node_t *rotate_right(tree_node_t *subtree);
tree_node_t *rotate_left(tree_node_t *subtree);
void inorder_destruction(tree_node_t *subtree, pthread_rwlock_t *lock, void (*key_destroy) (void *), void (*val_destroy) (void *));
int subtree_height(tree_node_t *subtree);
tree_node_t *create_tree_node(void *key, void *value, int keysize, int valsize);
void wait_on_references(tree_node_t **nodes, int num_nodes, pthread_rwlock_t *lock);
void dereference_and_destroy(void *voidarg);
void destroy_tree_node(tree_node_t *node, void (*key_destroy) (void *), void (*val_destroy) (void *));

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

// Function destroys a KeyTree, obviously.
void keytree_destroy(keytree_t *tree) {
  // No point in worrying about performance here. Just grab the write-lock at the
  // outset.
  pthread_rwlock_wrlock(&tree->lock);

  // Function waits for each nodes' references to reach zero, destroys them, and
  // returns.
  inorder_destruction(tree->root, &tree->lock, tree->key_destroy, tree->val_destroy);
  pthread_rwlock_unlock(&tree->lock);
  pthread_rwlock_destroy(&tree->lock);

  // Finish up.
  free(tree);
}

// Function takes care of inserting a key-value pair into the tree.
int keytree_insert(keytree_t *tree, void *key, void *value) {
  if (!tree || !key || !value) return KEYTREE_INVAL;

  // FIXME: Huge cop-out. I want to start getting to the actual project, and I'm
  // spending entirely too long on synchronization issues. Will revisit this at some
  // point in the future.
  pthread_rwlock_wrlock(&tree->lock);
  tree_node_t *current, *parent, *inserted = create_tree_node(key, value, tree->keysize, tree->valsize);

  // Check if root exists.
  if (!tree->root) {
    tree->root = inserted;
    tree->root->next = tree->root;
    tree->root->prev = tree->root;
    tree->size++;
    pthread_rwlock_unlock(&tree->lock);
    return KEYTREE_SUCCESS;
  }

  // Since we're holding the write-lock, this becomes very simple. Find insertion
  // point.
  stack_t *stack = internal_traverse(tree, key, 0);

  // Check to make sure they key doesn't already exist in the tree.
  stack_peek(stack, &parent);
  if (!tree->compare(key, parent->key)) {
    // Duplicate key.
    pthread_rwlock_unlock(&tree->lock);
    destroy_tree_node(inserted, tree->key_destroy, tree->val_destroy);
    destroy_stack(stack);
    return KEYTREE_DUPLICATE;
  }

  // Hook our new node into the tree.
  if (tree->compare(key, parent->key) > 0) parent->right = inserted;
  else parent->left = inserted;

  // Work our way up the insertion stack, rebalancing all the way.
  tree_node_t *current_parent;
  while (stack_pop(stack, &current) == STACK_SUCCESS) {
    // Balance.
    int retval = stack_peek(stack, &current_parent);
    if (retval != STACK_SUCCESS) tree->root = balance(current);
    else if (tree->compare(current->key, current_parent->key) > 0) current_parent->right = balance(current);
    else current_parent->left = balance(current);
  }

  // Now that the value has been inserted into the tree, hook it into the list.
  // Need to start by finding either the inorder predecessor or successor.
  tree_node_t *prev = NULL, *next = NULL;
  if (inserted->left) {
    // If a left child exists, inorder predecessor exists all the way to the right
    // of it.
    prev = inserted->left;
    while (prev->right) prev = prev->right;
  } else if (inserted->right) {
    // If a right child exists, inorder successor exists all the way to the left
    // of it.
    next = inserted->right;
    while (next->left) next = next->left;
  } else {
    // Node has no children. The fact that we got here means that we're inserting,
    // and that the root already exists. Therefore a parent must exist for the current node,
    // which, if it's larger, is the inorder successor, and if it's smaller is the inorder
    // predecessor. Grab it.
    if (tree->compare(parent->key, key) > 0) next = parent;
    else prev = parent;
  }

  // Hook up the links.
  if (prev) {
    next = prev->next;
    prev->next = inserted;
    inserted->prev = prev;
    inserted->next = next;
    next->prev = inserted;
  } else if (next) {
    prev = next->prev;
    next->prev = inserted;
    inserted->next = next;
    prev->next = inserted;
    inserted->prev = prev;
  }

  // Node is fully inserted in the tree. Increase count.
  tree->size++;

  // Unlock, clean up, and return.
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

  // Read lock does not need to be held for the following comparison line.
  // The only functions that can mutate the tree are keytree_insert, and
  // keytree_remove, and while they could reorganize the tree on us, we've
  // already found our node, and we still hold a reference to it, so it can't be freed
  // yet, and keytree_insert doesn't mutate in place.
  tree_node_t *target;
  int retval = stack_peek(stack, &target);
  if (retval == STACK_SUCCESS && !tree->compare(target->key, key)) {
    // This is the node we're looking for.
    memcpy(valbuf, target->value, tree->valsize);
    success = 1;
  }

  // Release our references.
  destroy_stack(stack);

  return success ? KEYTREE_SUCCESS : KEYTREE_NO_SUCH_ELEMENT;
}

// Function takes care of removing a key-value pair from the tree.
// If other threads are referencing the node we want to delete, function blocks
// until they release their references.
int keytree_remove(keytree_t *tree, void *key, void *valbuf) {
  if (!tree || !key) return KEYTREE_INVAL;

  // FIXME: Huge cop-out.
  pthread_rwlock_wrlock(&tree->lock);

  // Traverse tree to find the element we want to remove.
  stack_t *stack = internal_traverse(tree, key, 0);

  // Since we're holding the write-lock, this suddenly becomes very straightforward.
  tree_node_t *removed, *parent, *successor, *current;
  int retval = stack_pop(stack, &removed);
  if (retval == STACK_SUCCESS && !tree->compare(removed->key, key)) {
    // Check if we have a parent of if we're removing the root.
    int parent_status = stack_peek(stack, &parent);
    int comparison = parent_status == STACK_SUCCESS ? tree->compare(key, parent->key) : 0;

    // Figure out how much work we need to do.
    if (!removed->left && !removed->right) {
      // Easy life. Node has no children. Wait for references to hit zero and remove.
      wait_on_references(&removed, 1, &tree->lock);
      if (parent_status == STACK_SUCCESS) {
        // General case.
        if (comparison > 0) parent->right = NULL;
        else parent->left = NULL;
      } else {
        // Special case where we're removing the root node, and no other nodes are
        // in the tree.
        tree->root = NULL;
      }
    } else if (removed->right && !removed->left) {
      // 1 child. Need to reassign a child, but that's it.
      // Wait for references to hit zero and remove.
      wait_on_references(&removed, 1, &tree->lock);
      if (parent_status == STACK_SUCCESS) {
        // General case.
        if (comparison > 0) parent->right = removed->right;
        else parent->left = removed->right;
      } else {
        // Special case where we're removing the root node with only a right child.
        tree->root = removed->right;
      }
    } else if (removed->left && !removed->right) {
      // 1 child. Need to reassign a child, but that's it.
      // Wait for references to hit zero and remove.
      wait_on_references(&removed, 1, &tree->lock);
      if (parent_status == STACK_SUCCESS) {
        // General case.
        if (comparison > 0) parent->right = removed->left;
        else parent->left = removed->left;
      } else {
        // Special case where we're removing the root node with only a left child.
        tree->root = removed->left;
      }
    } else {
      // Two children. Time to find the inorder successor.
      stack_t *successor_stack = create_stack(free, sizeof(tree_node_t *));
      current = removed->right;
      while (current) {
        stack_push(successor_stack, &current);
        current = current->left;
      }
      stack_pop(successor_stack, &successor);

      // Alright, we have to start mutating things. Wait for references to hit
      // zero on the removed and successor nodes.
      tree_node_t *modified[2];
      modified[0] = removed;
      modified[1] = successor;
      wait_on_references(modified, 2, &tree->lock);

      // Remove successor from old position in the tree and assign new children.
      retval = stack_peek(successor_stack, &current);
      if (retval == STACK_SUCCESS) {
        // If successor is removed->right, there's nothing to do as its parent
        // will be removed anyways. If not, do this.
        // We know by definition that successor->left is NULL.
        current->left = successor->right;
        successor->right = removed->right;
      }
      successor->left = removed->left;

      // Replace deleted node with successor.
      if (parent_status == STACK_SUCCESS) {
        // General case.
        if (comparison > 0) parent->right = successor;
        else parent->left = successor;
      } else {
        // Special case where we're deleting the root node.
        tree->root = successor;
      }

      // Rebalance nodes visited on the way to the successor.
      while (stack_pop(successor_stack, &current) == STACK_SUCCESS) {
        retval = stack_peek(successor_stack, &parent);

        if (retval != STACK_SUCCESS) parent = successor;
        if (tree->compare(current->key, parent->key) > 0) parent->right = balance(current);
        else parent->left = balance(current);
      }
      destroy_stack(successor_stack);

      // We're going to use the stack for general rebalancing, so push the
      // successor onto the top to make sure it's rebalanced.
      // We also need to increment the reference count of the successor as it will
      // be decremented during balancing.
      __sync_fetch_and_add(&successor->references, 1);
      stack_push(stack, &successor);
    }

    // Time to rebalance!
    while (stack_pop(stack, &current) == STACK_SUCCESS) {
      retval = stack_peek(stack, &parent);
      if (retval != STACK_SUCCESS) tree->root = balance(current);
      else if (tree->compare(current->key, parent->key) > 0) parent->right = balance(current);
      else parent->left = balance(current);
    }

    // Update links in the list.
    tree_node_t *prev = removed->prev, *next = removed->next;
    prev->next = next;
    next->prev = prev;

    // All references to the node have been removed from the tree. Release
    // references, decrease size, and lock.
    tree->size--;
    pthread_rwlock_unlock(&tree->lock);
    destroy_stack(stack);

    // Copy the data out if the user gave us somewhere to put it.
    if (valbuf) memcpy(valbuf, removed->value, tree->valsize);

    // Free the node.
    destroy_tree_node(removed, tree->key_destroy, tree->val_destroy);

    return KEYTREE_SUCCESS;
  } else {
    // The element doesn't exist in the tree.
    pthread_rwlock_unlock(&tree->lock);
    destroy_stack(stack);
    return KEYTREE_NO_SUCH_ELEMENT;
  }
}

// Function allocates an interator and initializes it to the node with the given
// key. If the given key does not exist, returns NULL.
// If target key is NULL, initializes it to the smallest key.
keytree_iterator_t *keytree_iterate_start(keytree_t *tree, void *target_key) {
  if (!tree || !tree->root) return NULL;
  keytree_iterator_t *it = malloc(sizeof(keytree_iterator_t));

  if (it) {
    // Copy over the data.
    it->lock = &tree->lock;

    pthread_rwlock_rdlock(&tree->lock);
    if (target_key) {
      // Find the target node.
      stack_t *stack = internal_traverse(tree, target_key, 0);

      if (stack_pop(stack, &it->curr) == STACK_EMPTY) {
        // Key does not exist in tree.
        destroy_stack(stack);
        free(it);
        return NULL;
      }

      // Key was successfully found.
      destroy_stack(stack);
    } else {
      // User didn't provide a target key, find smallest node and start there.
      tree_node_t *current = tree->root;
      while (current->left) current = current->left;
      it->curr = current;
    }
    // Increase reference count for the current node to make sure it isn't freed
    // out from under us.
    __sync_fetch_and_add(&it->curr->references, 1);

    // Finish intializations.
    it->keysize = tree->keysize;
    it->valsize = tree->valsize;

    // Unlock the tree.
    pthread_rwlock_unlock(&tree->lock);
  }

  return it;
}

// Function copies data out for the current node, then moves forward.
int keytree_iterate_next(keytree_iterator_t *it, void *keybuf, void *valbuf) {
  if (!it) return KEYTREE_INVAL;
  else if (!it->curr) return KEYTREE_NO_SUCH_ELEMENT;

  // Lock the tree for reading.
  pthread_rwlock_rdlock(it->lock);

  // Copy the data into the buffers for the current node.
  memcpy(keybuf, it->curr->key, it->keysize);
  memcpy(valbuf, it->curr->value, it->valsize);

  // Update references.
  __sync_fetch_and_sub(&it->curr->references, 1);
  if (it->curr->next) __sync_fetch_and_add(&it->curr->next->references, 1);

  // Update pointers, unlock, and return.
  it->curr = it->curr->next;
  pthread_rwlock_unlock(it->lock);
  return KEYTREE_SUCCESS;
}

// Function copies data out for the current node, then moves back.
int keytree_iterate_prev(keytree_iterator_t *it, void *keybuf, void *valbuf) {
  if (!it) return KEYTREE_INVAL;
  else if (!it->curr) return KEYTREE_NO_SUCH_ELEMENT;

  // Lock the tree for reading.
  pthread_rwlock_rdlock(it->lock);

  // Copy the data into the buffers for the current node.
  memcpy(keybuf, it->curr->key, it->keysize);
  memcpy(valbuf, it->curr->value, it->valsize);

  // Update references.
  __sync_fetch_and_sub(&it->curr->references, 1);
  if (it->curr->prev) __sync_fetch_and_add(&it->curr->prev->references, 1);

  // Update pointers, unlock, and return.
  it->curr = it->curr->prev;
  pthread_rwlock_unlock(it->lock);
  return KEYTREE_SUCCESS;
}

// Function stops an interation.
// Basically just decrements the reference for the current node and then frees
// the iterator.
// Not really any need to acquire the lock.
void keytree_iterate_stop(keytree_iterator_t *it) {
  if (!it) return;
  if (it->curr) __sync_fetch_and_sub(&it->curr->references, 1);
  free(it);
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

tree_node_t *balance(tree_node_t *subtree) {
  if (subtree_height(subtree->left) - subtree_height(subtree->right) > 1) {
    if (subtree_height(subtree->left->left) >= subtree_height(subtree->left->right)) {
      subtree = rotate_left(subtree);
    } else {
      subtree->left = rotate_right(subtree->left);
      subtree = rotate_left(subtree);
    }
  } else if (subtree_height(subtree->right) - subtree_height(subtree->left) > 1) {
    if (subtree_height(subtree->right->right) >= subtree_height(subtree->right->left)) {
      subtree = rotate_right(subtree);
    } else {
      subtree->right = rotate_left(subtree->right);
      subtree = rotate_right(subtree);
    }
  }

  // Update the height.
  subtree->height = MAX(subtree_height(subtree->left), subtree_height(subtree->right)) + 1;
  return subtree;
}

tree_node_t *rotate_right(tree_node_t *subtree) {
  tree_node_t *right_child = subtree->right;
  subtree->right = right_child->left;
  right_child->left = subtree;
  subtree->height = MAX(subtree_height(subtree->left), subtree_height(subtree->right)) + 1;
  right_child->height = MAX(subtree_height(right_child->right), subtree->height) + 1;
  return right_child;
}

tree_node_t *rotate_left(tree_node_t *subtree) {
  tree_node_t *left_child = subtree->left;
  subtree->left = left_child->right;
  left_child->right = subtree;
  subtree->height = MAX(subtree_height(subtree->left), subtree_height(subtree->right)) + 1;
  left_child->height = MAX(subtree_height(left_child->left), subtree->height) + 1;
  return left_child;
}

void inorder_destruction(tree_node_t *subtree, pthread_rwlock_t *lock, void (*key_destroy) (void *), void (*val_destroy) (void *)) {
  if (!subtree) return;

  tree_node_t *left_subtree = subtree->left, *right_subtree = subtree->right;
  inorder_destruction(left_subtree, lock, key_destroy, val_destroy);
  destroy_tree_node(subtree, key_destroy, val_destroy);
  inorder_destruction(right_subtree, lock, key_destroy, val_destroy);
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

// Function blocks until the given node's references have hit zero.
// Expects to be called with the write-lock held. Returns with it still held.
void wait_on_references(tree_node_t **nodes, int num_nodes, pthread_rwlock_t *lock) {
  struct timespec ts;
  for (int i = 0; 1; i++) {
    // Figure out if any references are still held.
    int safe = 1;
    for (int j = 0; j < num_nodes; j++) if (nodes[j]->references) safe = 0;
    if (safe) break;

    // References are still held. Get ready to sleep.
    pthread_rwlock_unlock(lock);
    if (i > 10) i = 10;

    // Figure out how long to sleep for. Exponential backoff with a cap of 1 second.
    int factor = 1 << i;
    unsigned long long total_wait = KEYTREE_WAIT_BASE * factor;
    ts.tv_sec = total_wait / 1000000000;
    ts.tv_nsec = total_wait % 1000000000;
    nanosleep(&ts, NULL);

    // Lock and reinitialize.
    pthread_rwlock_wrlock(lock);
  }
}

void dereference_and_destroy(void *voidarg) {
  tree_node_t **node_ptr = voidarg;
  __sync_fetch_and_sub(&((*node_ptr)->references), 1);
  free(node_ptr);
}

// Function takes care of destroying a tree node.
void destroy_tree_node(tree_node_t *node, void (*key_destroy) (void *), void (*val_destroy) (void *)) {
  key_destroy(node->key);
  val_destroy(node->value);
  free(node);
}

void print_tree(keytree_t *tree) {
  list_t *lst = create_list(sizeof(tree_node_t *), free);
  lpush(lst, &tree->root);

  tree_node_t *current;
  while (rpop(lst, &current) != LIST_EMPTY) {
    printf(" (%s) ", current->key);
    if (current->left) lpush(lst, &current->left);
    if (current->right) lpush(lst, &current->right);
  }
}
