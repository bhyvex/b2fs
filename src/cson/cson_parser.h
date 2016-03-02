#ifndef CSON_PARSER
#define CSON_PARSER

/*----- Numerical Constants -----*/

#define CSON_START_SIZE 64

/*----- Type Declarations -----*/

#ifndef CSON_OBJ_TYPE
#define CSON_OBJ_TYPE

typedef struct cson_object cson_object_t;

#endif

/*----- Parsing Functions -----*/

cson_object_t *cson_parse_string(char *json);
cson_object_t *cson_parse_file(FILE *json_file);
cson_object_t *cson_parse_filename(char *filename);

#endif
