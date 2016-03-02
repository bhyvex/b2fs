#ifndef CSON_OBJ
#define CSON_OBJ

/*----- Struct Declarations -----*/

#ifndef CSON_OBJ_TYPE
#define CSON_OBJ_TYPE

typedef struct cson_object cson_object_t;

#endif

/*----- Value Creation Functions -----*/

cson_object_t *create_cson_int(int value);
cson_object_t *create_cson_double(double value);
cson_object_t *create_cson_bool(int value);
cson_object_t *create_cson_string(char *value);
cson_object_t *create_cson_array(array_t *value);
cson_object_t *create_cson_hash(hash_t *value);

/*----- Intermediate Retrieval Functions -----*/

cson_object_t *cson_get_element(cson_object_t *obj, int index);
cson_object_t *cson_get_key(cson_object_t *obj, char *key);

/*----- Value Retrieval Functions -----*/

int *cson_get_int(cson_object_t *obj);
double *cson_get_double(cson_object_t *obj);
int *cson_get_bool(cson_object_t *obj);
char *cson_get_string(cson_object_t *obj);

/*----- Introspection Functions -----*/

int cson_is_int(cson_object_t *obj);
int cson_is_double(cson_object_t *obj);
int cson_is_bool(cson_object_t *obj);
int cson_is_string(cson_object_t *obj);
int cson_is_array(cson_object_t *obj);
int cson_is_hash(cson_object_t *obj);

#endif
