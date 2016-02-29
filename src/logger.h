typedef enum b2fs_loglevel {
  LEVEL_DEBUG,
  LEVEL_INFO,
  LEVEL_ERROR
} b2fs_loglevel_t;

#ifdef DEBUG

#define write_log(level, ...)                                                 \
  do {                                                                        \
    printf(__VA_ARGS__);                                                      \
  } while (0);

#elif INFO

#define write_log(level, ...)                                                 \
  do {                                                                        \
    if (level == LEVEL_INFO) printf(__VA_ARGS__)                              \
    else if (level == LEVEL_ERROR) fprintf(stderr, __VA_ARGS__);              \
  } while (0);

#else

#define write_log(level, ...)                                                 \
  do {                                                                        \
    if (level == LEVEL_ERROR) fprintf(stderr, __VA_ARGS__);                   \
  } while (0);

#endif

#define log_tree_key(node, message)                                           \
  write_log(LEVEL_DEBUG, "%s: %s\n", message, *(char **) node->key);

#define LOG_KEY(data, key, context)                                           \
  do {                                                                        \
    write_log(LEVEL_DEBUG, "B2FS: Encountered unexpected key in %s: %.*s\n",  \
        context, key->end - key->start, data + key->start);                   \
  } while (0);
