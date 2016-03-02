/*----- Includes -----*/

#include <stdlib.h>
#include <string.h>
#include "cson_obj.h"
#include "../structures/array.h"
#include "../structures/hash.h"

/*----- Bitmasks -----*/

#define CSON_IS_INTEGER 0x01
#define CSON_IS_DOUBLE  0x02
#define CSON_IS_BOOL    0x04
#define CSON_IS_STRING  0x08
#define CSON_IS_ARRAY   0x10
#define CSON_IS_OBJECT  0x20

/*----- Type Definitions -----*/

struct cson_object {
  unsigned char type;
  void *data;
};

/*----- Value Creation Implementations -----*/

cson_object_t *create_cson_int(int value) {
  cson_object_t *new_obj = malloc(sizeof(cson_object_t));
  new_obj->data = malloc(sizeof(int));
  new_obj->type |= CSON_IS_INTEGER;
  memcpy(new_obj->data, &value, sizeof(int));
  return new_obj;
}

cson_object_t *create_cson_double(double value) {
  cson_object_t *new_obj = malloc(sizeof(cson_object_t));
  new_obj->data = malloc(sizeof(double));
  new_obj->type |= CSON_IS_DOUBLE;
  memcpy(new_obj->data, &value, sizeof(double));
  return new_obj;
}

cson_object_t *create_cson_bool(int value) {
  cson_object_t *new_obj = malloc(sizeof(cson_object_t));
  new_obj->data = malloc(sizeof(int));
  new_obj->type |= CSON_IS_BOOL;
  memcpy(new_obj->data, &value, sizeof(int));
  return new_obj;
}

cson_object_t *create_cson_string(char *value) {
  cson_object_t *new_obj = malloc(sizeof(cson_object_t));
  new_obj->data = value;
  new_obj->type |= CSON_IS_STRING;
  return new_obj;
}

cson_object_t *create_cson_array(array_t *value) {
  cson_object_t *new_obj = malloc(sizeof(cson_object_t));
  new_obj->data = value;
  new_obj->type |= CSON_IS_ARRAY;
  return new_obj;
}

cson_object_t *create_cson_hash(hash_t *value) {
  cson_object_t *new_obj = malloc(sizeof(cson_object_t));
  new_obj->data = value;
  new_obj->type |= CSON_IS_OBJECT;
  return new_obj;
}

/*----- Intermediate Retrieval Implementations -----*/

cson_object_t *cson_get_element(cson_object_t *obj, int index) {
  if (obj->type & CSON_IS_ARRAY) {
    cson_object_t *elem;
    return array_retrieve(obj->data, index, &elem) == ARRAY_SUCCESS ? elem : NULL;
  } else {
    return NULL;
  }
}

cson_object_t *cson_get_key(cson_object_t *obj, char *key) {
  if (obj->type & CSON_IS_OBJECT) {
    cson_object_t *prop;
    return hash_get(obj->data, key, &prop) == HASH_SUCCESS ? prop : NULL;
  } else {
    return NULL;
  }
}

/*----- Value Retrieval Implementations -----*/

int *cson_get_int(cson_object_t *obj) {
  return obj->type & CSON_IS_INTEGER ? obj->data : NULL;
}

double *cson_get_double(cson_object_t *obj) {
  return obj->type & CSON_IS_DOUBLE ? obj->data : NULL;
}

int *cson_get_bool(cson_object_t *obj) {
  return obj->type & CSON_IS_BOOL ? obj->data : NULL;
}

char *cson_get_string(cson_object_t *obj) {
  return obj->type & CSON_IS_STRING ? obj->data : NULL;
}

/*----- Introspection Implementations -----*/

int cson_is_int(cson_object_t *obj) {
  return obj->type & CSON_IS_INTEGER ? 1 : 0;
}

int cson_is_double(cson_object_t *obj) {
  return obj->type & CSON_IS_DOUBLE ? 1 : 0;
}

int cson_is_bool(cson_object_t *obj) {
  return obj->type & CSON_IS_BOOL ? 1 : 0;
}

int cson_is_string(cson_object_t *obj) {
  return obj->type & CSON_IS_STRING ? 1 : 0;
}

int cson_is_array(cson_object_t *obj) {
  return obj->type & CSON_IS_ARRAY ? 1 : 0;
}

int cson_is_hash(cson_object_t *obj) {
  return obj->type & CSON_IS_OBJECT ? 1 : 0;
}
