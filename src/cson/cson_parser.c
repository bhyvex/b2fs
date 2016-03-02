/*----- System Includes -----*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <ctype.h>

/*----- Local Includes -----*/

#include "../structures/array.h"
#include "../structures/hash.h"
#include "cson_parser.h"
#include "cson_obj.h"

/*----- Macro Function Declarations -----*/

#define ADVANCE() array_retrieve(tokens, (*index)++, &token)

#define HASH_ENFORCE_TOKEN(target)                            \
  do {                                                        \
    if (*token != target) {                                   \
      if (*token == '}') break;                               \
      hash_destroy(data);                                     \
      return NULL;                                            \
    }                                                         \
  } while (0);

#define ARRAY_ENFORCE_TOKEN(target)                           \
  do {                                                        \
    if (*token != target) {                                   \
      if (*token == ']') break;                               \
      array_destroy(data);                                    \
      return NULL;                                            \
    }                                                         \
  } while (0);

#define PEEK_ADVANCE_AND_RETURN(target, tmp)                  \
  do {                                                        \
    array_retrieve(tokens, *index, &tmp);                     \
    if (*tmp == target) {                                     \
      (*index)++;                                             \
      return new_obj;                                         \
    }                                                         \
  } while (0);

/*----- Internal Parsing Function Stub Declarations -----*/

array_t *tokenize(char *json);
cson_object_t *literal_switch(array_t *tokens, int *index);

cson_object_t *parse_hash(array_t *tokens, int *index);
cson_object_t *parse_array(array_t *tokens, int *index);
cson_object_t *parse_string(array_t *tokens, int *index);
cson_object_t *parse_bool(char *boolean);
cson_object_t *parse_double(char *decimal);
cson_object_t *parse_int(char *integer);

void dereference_and_destroy(void *voidarg);

/*----- Public Parsing Function Implementations -----*/

cson_object_t *cson_parse_string(char *json) {
  array_t *tokens = tokenize(json);
  int index = 0;
  return literal_switch(tokens, &index);
}

cson_object_t *cson_parse_file(FILE *json_file) {
  int size = CSON_START_SIZE;
  char *json = malloc(sizeof(char) * size);
  if (json) {
    for (int i = 0; 1; i++) {
      char c = getc(json_file);
      if (c == EOF) {
        json[i] = '\0';
        break;
      }
      json[i] = c;
      if (i == size - 1) {
        size *= 2;
        char *resized = realloc(json, size);
        if (!resized) return NULL;
        if (json != resized) free(json);
        json = resized;
      }
    }
    cson_object_t *result = cson_parse_string(json);
    free(json);
    return result;
  } else {
    return NULL;
  }
}

cson_object_t *cson_parse_filename(char *filename) {
  struct stat buf;
  stat(filename, &buf);

  if (S_ISREG(buf.st_mode)) {
    FILE *file = fopen(filename, "r");
    cson_object_t *result = cson_parse_file(file);
    fclose(file);
    return result;
  } else {
    return NULL;
  }
}

/*----- Internal Parsing Function Implementations -----*/

array_t *tokenize(char *json) {
  array_t *tokens = create_array(sizeof(char *), dereference_and_destroy);
  int length = strlen(json);

  for (int i = 0; i < length; i++) {
    char c = json[i], *tmp;
    if (isspace(c)) continue;

    if (c == '"') {
      tmp = malloc(sizeof(char) * 2);
      *tmp = c;
      *(tmp + 1) = '\0';
      array_push(tokens, &tmp);
      i++;

      int diff;
      char prev = '\0';
      for (diff = 0; i + diff < length && (json[i + diff] != '"' || prev == '\\'); diff++) prev = json[i + diff];
      if (diff) {
        tmp = malloc(sizeof(char) * (diff + 1));
        memcpy(tmp, json + i, diff);
        *(tmp + diff) = '\0';
        array_push(tokens, &tmp);
      }

      i += diff;
      c = json[i];
      if (c != '"') {
        array_destroy(tokens);
        return NULL;
      }

      tmp = malloc(sizeof(char) * 2);
      *tmp = c;
      *(tmp + 1) = '\0';
      array_push(tokens, &tmp);
    } else if (c >= '0' && c <= '9' || c == 't' || c == 'f' || c == 'n') {
      int diff;
      char start = c >= '0' && c <= '9' ? '0' : 'a', end = c >= '0' && c <= '9' ? '9' : 'z';
      for (diff = 0; diff < length && (json[i + diff] >= start && json[i + diff] <= end || (start == '0' && json[i + diff] == '.')); diff++);
      tmp = malloc(sizeof(char) * (diff + 2));
      memcpy(tmp, json + i, diff);
      *(tmp + diff) = '\0';
      i += diff - 1;
      array_push(tokens, &tmp);
    } else {
      tmp = malloc(sizeof(char) * 2);
      *tmp = c;
      *(tmp + 1) = '\0';
      array_push(tokens, &tmp);
    }
  }

  return tokens;
}

cson_object_t *literal_switch(array_t *tokens, int *index) {
  char *token;
  array_retrieve(tokens, (*index)++, &token);
  switch (*token) {
    case '{':
      return parse_hash(tokens, index);
    case '[':
      return parse_array(tokens, index);
    case '"':
      return parse_string(tokens, index);
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
      if (strchr(token, '.')) {
        return parse_double(token);
      } else {
        return parse_int(token);
      }
    case 't':
    case 'f':
      return parse_bool(token);
    case 'n':
      if (!strcmp("null", token)) return create_cson_hash(NULL);
      else return NULL;
    default:
      return NULL;
  }
}


cson_object_t *parse_hash(array_t *tokens, int *index) {
  char *tmp, *token;
  hash_t *data = create_hash(sizeof(cson_object_t *), dereference_and_destroy);
  cson_object_t *new_obj = create_cson_hash(data);
  PEEK_ADVANCE_AND_RETURN('}', tmp);

  for (array_retrieve(tokens, (*index)++, &token); 1; array_retrieve(tokens, (*index)++, &token)) {
    HASH_ENFORCE_TOKEN('"');
    ADVANCE();

    char *key = token;
    ADVANCE();

    HASH_ENFORCE_TOKEN('"');
    ADVANCE();
    HASH_ENFORCE_TOKEN(':');

    cson_object_t *value = literal_switch(tokens, index);
    if (!value) {
      hash_destroy(data);
      return NULL;
    }
    hash_put(data, key, value);

    ADVANCE();
    HASH_ENFORCE_TOKEN(',');
  }

  return new_obj;
}

cson_object_t *parse_array(array_t *tokens, int *index) {
  char *token = NULL, *tmp;
  array_t *data = create_array(sizeof(cson_object_t *), dereference_and_destroy);
  cson_object_t *new_obj = create_cson_array(data);
  PEEK_ADVANCE_AND_RETURN(']', tmp);

  while (1) {
    array_push(data, literal_switch(tokens, index));
    ADVANCE();
    ARRAY_ENFORCE_TOKEN(',');
  }

  return new_obj;
}

cson_object_t *parse_string(array_t *tokens, int *index) {
  char *str, *copy;
  array_retrieve(tokens, (*index)++, &str);
  copy = malloc(sizeof(char) * (strlen(str) + 1));
  strcpy(copy, str);

  cson_object_t *new_obj = create_cson_string(copy);
  (*index)++;
  return new_obj;
}

cson_object_t *parse_bool(char *boolean) {
  int value;
  if (!strcmp(boolean, "true")) value = 1;
  else if (!strcmp(boolean, "false")) value = 0;
  else return NULL;
  cson_object_t *new_obj = create_cson_bool(value);
  return new_obj;
}

cson_object_t *parse_double(char *decimal) {
  double value;
  sscanf(decimal, "%lf", &value);
  cson_object_t *new_obj = create_cson_double(value);
  return new_obj;
}

cson_object_t *parse_int(char *integer) {
  int value;
  sscanf(integer, "%d", &value);
  cson_object_t *new_obj = create_cson_int(value);
  return new_obj;
}

void dereference_and_destroy(void *voidarg) {
  char **arg = voidarg;
  free(*arg);
}
