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
void hook_up(keytree_t *tree, void *key);
void inorder_destruction(tree_node_t *subtree, pthread_rwlock_t *lock, void (*key_destroy) (void *), void (*val_destroy) (void *));
int subtree_height(tree_node_t *subtree);
tree_node_t *create_tree_node(void *key, void *value, int keysize, int valsize);
void dereference_and_destroy(void *voidarg);
void destroy_tree_node(tree_node_t *node, pthread_rwlock_t *lock, void (*key_destroy) (void *), void (*val_destroy) (void *), int release);

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
  // This whole dance is necessary so that we can avoid acquiring the write-lock
  // for as long as possible.
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
    // Insert.
    if (tree->compare(key, current->key) > 0 && !current->right) {
      current->right = create_tree_node(key, value, tree->keysize, tree->valsize);
    } else if (tree->compare(key, current->key) < 0 && !current->left) {
      current->left = create_tree_node(key, value, tree->keysize, tree->valsize);
    }

    // Balance.
    tree_node_t *parent = stack_peek(stack);
    if (tree->compare(current->key, parent->key) > 0) parent->right = balance(current);
    else parent->left = balance(current);
  }

  // Now that the value has been inserted into the tree, hook it into the list.
  // Unfortunately this can't easily be done during insertion as the structure
  // of the tree is still subject to change.
  // Basically I'm lazy and don't care to figure it out.
  hook_up(tree, key);

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

  // Release our references.
  destroy_stack(stack);

  return success ? KEYTREE_SUCCESS : KEYTREE_NO_SUCH_ELEMENT;
}

// Function takes care of removing a key-value pair from the tree.
// If other threads are referencing the node we want to delete, function blocks
// until they release their references.
int keytree_remove(keytree_t *tree, void *key, void *valbuf) {
  if (!tree || !key) return KEYTREE_INVAL;
  if (!tree->root) return KEYTREE_NO_SUCH_ELEMENT;

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

    // Forfeit our references to the deleted nodes, acquire write lock, and attempt
    // to find the node in the tree again.
    // If there is contention, and there are multiple threads trying to delete
    // this node simulatenously, we are either the leader or a follower in this
    // operation.
    // If we are the leader, we will find the node in the tree on the second go,
    // we will remove it from the tree, and we will wait for the references to hit
    // zero to free the node.
    // If we are a follower, we will not find the node in the tree, and will give up.
    // We must forfeit our references before acquiring the write lock as otherwise
    // multiple deleters could deadlock.
    // If there are other readers in the tree, holding a reference to the node, the
    // leader will wait until they have exited the tree to free the node.
    // The reason for this whole complicated dance is to avoid acquiring the
    // write-lock if the node was never in the tree in the first place, and because
    // read-locks cannot be atomically converted into write-locks.
    destroy_stack(stack);
    pthread_rwlock_wrlock(&tree->lock);

    // Note that we do not acquire a read lock for this traversal.
    stack = internal_traverse(tree, key, 0);
    if (!tree->compare(((tree_node_t *) stack_peek(stack))->key, key)) {
      // We are the leader (or there is no contention)!
      // Remove and rebalance.
      tree_node_t *parent, *current, *successor;

      // We permanently release our reference to the deleted node, and remove it
      // from the stack (will be used later for rebalancing), but not the parent
      // yet.
      stack_pop(stack, &removed);
      parent = stack_peek(stack);

      // Figure out how much work we need to do.
      int comparison = parent ? tree->compare(parent->key, key) : 0;
      if (!removed->left && !removed->right) {
        // Easy life. Node has no children.
        if (parent) {
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
        if (parent) {
          // General case.
          if (comparison > 0) parent->right = removed->right;
          else parent->left = removed->right;
        } else {
          // Special case where we're removing the root node with only a right child.
          tree->root = removed->right;
        }
      } else if (removed->left && !removed->right) {
        // 1 child. Need to reassign a child, but that's it.
        if (parent) {
          // General case.
          if (comparison > 0) parent->right = removed->left;
          else parent->left = removed->left;
        } else {
          // Special case where we're removing the root node with only a left child.
          tree->root = removed->left;
        }
      } else {
        // Two children. Time to find the inorder successor.
        // We're holding the write-lock, so no point to incrementing references.
        stack_t *successor_stack = create_stack(free, sizeof(tree_node_t *));
        current = removed->right;
        while (current) {
          stack_push(successor_stack, current);
          current = current->left;
        }
        stack_pop(successor_stack, &successor);

        // Remove successor from old position in the tree and assign new children.
        if (stack_peek(successor_stack)) {
          // If successor is removed->right, there's nothing to do as its parent
          // will be removed anyways. If not, do this.
          // We know by definition that successor->left is NULL.
          ((tree_node_t *) stack_peek(successor_stack))->left = successor->right;
          successor->right = removed->right;
        }
        successor->left = removed->left;

        // Replace deleted node with successor.
        if (parent) {
          // General case.
          if (comparison > 0) parent->right = successor;
          else parent->left = successor;
        } else {
          // Special case where we're deleting the root node.
          tree->root = successor;
        }

        // Rebalance nodes visited on the way to the successor.
        while (stack_pop(successor_stack, &current) == STACK_SUCCESS) {
          parent = stack_peek(successor_stack);
          if (tree->compare(current->key, parent->key) > 0) parent->right = balance(current);
          else parent->left = balance(current);
        }
        destroy_stack(successor_stack);

        // We're going to use the stack for general rebalancing, so push the
        // successor onto the top to make sure it's rebalanced.
        // We also need to increment the reference count of the successor as it will
        // be decremented during balancing.
        __sync_fetch_and_add(&successor->references, 1);
        stack_push(stack, successor);
      }

      // Time to rebalance!
      while (stack_pop(stack, &current) == STACK_SUCCESS) {
        tree_node_t *parent = stack_peek(stack);
        if (tree->compare(current->key, parent->key) > 0) parent->right = balance(current);
        else parent->left = balance(current);
      }

      // Update links in the list.
      tree_node_t *prev = removed->prev, *next = removed->next;
      prev->next = next;
      next->prev = prev;

      // Oh Jesus. We're done. Talk about an exhausting function. Clean up and return.
      destroy_stack(stack);

      // Copy the data out if the user gave us somewhere to do it.
      if (valbuf) memcpy(valbuf, removed->value, tree->valsize);

      // Note that this will block until all other references to the node have been
      // released, and that it will also release the write-lock.
      destroy_tree_node(removed, &tree->lock, tree->key_destroy, tree->val_destroy, 1);
      return KEYTREE_SUCCESS;
    } else {
      // We are a follower...
      // Nothing left to do. Leave removal up to leader (may already be done).
      destroy_stack(stack);
      pthread_rwlock_unlock(&tree->lock);
      return KEYTREE_NO_SUCH_ELEMENT;
    }
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

    if (target_key) {
      // Find the target node.
      stack_t *stack = internal_traverse(tree, target_key, 1);

      if (stack_pop(stack, &it->curr) == STACK_EMPTY) {
        // Key does not exist in tree.
        destroy_stack(stack);
        pthread_rwlock_unlock(&tree->lock);
        free(it);
        return NULL;
      }

      // Key was successfully found.
      destroy_stack(stack);
    } else {
      // User didn't provide a target key, find smallest node and start there.
      pthread_rwlock_rdlock(&tree->lock);
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
// FIXME: Could probably be done without locking. Reference counts should be enough to
// protect access. Revisit.
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
// FIXME: Could probably be done without locking. Reference counts should be enough to
// protect access. Revisit.
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
  subtree->height = MAX(subtree_height(subtree->left), subtree_height(subtree->right)) + 1;
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
  left_child->height = MAX(subtree_height(left_child->left), subtree->height);
  return left_child;
}

// Function hooks a just inserted node with the given key into the list.
void hook_up(keytree_t *tree, void *key) {
  stack_t *stack = internal_traverse(tree, key, 0);
  tree_node_t *prev = NULL, *curr, *next = NULL;
  stack_pop(stack, &curr);

  // First try finding the inorder predecessor.
  if (curr->left) {
    // If a left child exists, inorder predecessor exists all the way to the right
    // of it.
    prev = curr->left;
    while (prev->right) prev = prev->right;
  } else {
    // We may need to use it again, so duplicate the stack.
    stack_t *copy = stack_dup(stack, free);

    // If no left child exists, inorder predecessor, if it exists, is the first
    // parent in the stack that is smaller than its child.
    tree_node_t *child = curr, *parent;
    while (stack_pop(copy, &parent) == STACK_SUCCESS) {
      if (tree->compare(parent, child) < 0) {
        // We've found it!
        prev = parent;
        break;
      }
      child = parent;
    }
    destroy_stack(copy);
  }

  // If we couldn't find a predecessor, we've inserted the new smallest element into
  // the tree. Instead find the successor.
  if (curr->right && !prev) {
    // If a right child exists, inorder successor exists all the way to the left
    // of it.
    next = curr->right;
    while (next->left) next = next->left;
  } else if (!prev) {
    // If no left child exists, inorder successor is the first parent in the stack
    // that is larger than its child.
    tree_node_t *child = curr, *parent;
    while (stack_pop(stack, &parent) == STACK_SUCCESS) {
      if (tree->compare(parent, child) > 0) {
        // We've found it!
        next = parent;
        break;
      }
      child = parent;
    }
  }
  destroy_stack(stack);

  // Hook up the links.
  if (prev) {
    next = prev->next;
    prev->next = curr;
    curr->prev = prev;
    curr->next = next;
    next->prev = curr;
  } else if (next) {
    prev = next->prev;
    next->prev = curr;
    curr->next = next;
    prev->next = curr;
    curr->prev = prev;
  }
}

void inorder_destruction(tree_node_t *subtree, pthread_rwlock_t *lock, void (*key_destroy) (void *), void (*val_destroy) (void *)) {
  if (!subtree) return;

  tree_node_t *left_subtree = subtree->left, *right_subtree = subtree->right;
  inorder_destruction(left_subtree, lock, key_destroy, val_destroy);
  destroy_tree_node(subtree, lock, key_destroy, val_destroy, 0);
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

void dereference_and_destroy(void *voidarg) {
  tree_node_t **node_ptr = voidarg;
  __sync_fetch_and_sub(&((*node_ptr)->references), 1);
  free(node_ptr);
}

// Function takes care of destroying a tree node.
// Function blocks until node references hit 0.
// Function expects wrlock to be held when called.
void destroy_tree_node(tree_node_t *node, pthread_rwlock_t *lock, void (*key_destroy) (void *), void (*val_destroy) (void *), int release) {
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
  if (release) pthread_rwlock_unlock(lock);
}
