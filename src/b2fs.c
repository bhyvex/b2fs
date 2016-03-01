/*----- Constants -----*/

// Error codes.
#define B2FS_SUCCESS 0x00
#define B2FS_GENERIC_ERROR -0x01
#define B2FS_INVAL -0x02
#define B2FS_NOMEM -0x04
#define B2FS_GENERIC_NETWORK_ERROR -0x08
#define B2FS_NETWORK_ACCESS_ERROR -0x0100
#define B2FS_NETWORK_INTERN_ERROR -0x0101
#define B2FS_NETWORK_API_ERROR -0x0102

// Numerical Constants.
#define B2FS_ACCOUNT_ID_LEN 16
#define B2FS_APP_KEY_LEN 64
#define B2FS_TOKEN_LEN 128
#define B2FS_SMALL_GENERIC_BUFFER 256
#define B2FS_MED_GENERIC_BUFFER 1024
#define B2FS_LARGE_GENERIC_BUFFER 4096
#define B2FS_CHUNK_SIZE (1024 * 1024 * 16)
#define B2FS_INIT_CHUNK_NUM 10

#define FUSE_USE_VERSION 30

/*----- System Includes -----*/

#include <fuse.h>
#include <curl/curl.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>

/*----- Local Includes -----*/

#include "b64/cencode.h"
#include "jsmn/jsmn.h"
#include "structures/hash.h"
#include "structures/bitmap.h"
#include "structures/keytree.h"

/*----- Macro Declarations -----*/

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

#define LOG_KEY(data, key, context)                                           \
  do {                                                                        \
    write_log(LEVEL_DEBUG, "B2FS: Encountered unexpected key in %s: %.*s\n",  \
        context, key->end - key->start, data + key->start);                   \
  } while (0);

/*----- Type Declarations -----*/

typedef enum b2fs_loglevel {
  LEVEL_DEBUG,
  LEVEL_INFO,
  LEVEL_ERROR
} b2fs_loglevel_t;

typedef enum b2fs_entry_type {
  TYPE_DIRECTORY,
  TYPE_FILE
} b2fs_entry_type_t;

typedef struct b2_account {
  char account_id[B2FS_ACCOUNT_ID_LEN];
  char app_key[B2FS_APP_KEY_LEN];
} b2_account_t;

typedef struct b2fs_file_chunk {
  int chunk_num;
  char data[B2FS_CHUNK_SIZE];
} b2fs_file_chunk_t;

typedef struct b2fs_file_entry {
  bitmap_t *chunkmap;
  keytree_t *chunks;
  int readers, writers, size, dynamic;
} b2fs_file_entry_t;

typedef struct b2fs_hash_entry {
  b2fs_entry_type_t type;
  union {
    b2fs_file_entry_t file;
    hash_t *directory;
  };
} b2fs_hash_entry_t;

typedef struct b2fs_state {
  char token[B2FS_TOKEN_LEN], api_url[B2FS_TOKEN_LEN];
  char down_url[B2FS_TOKEN_LEN], bucket[B2FS_SMALL_GENERIC_BUFFER];
  hash_t *fs_cache;
  int exclusive;
} b2fs_state_t;

/*----- Local Function Declarations -----*/

// Filesystem Functions.
void *b2fs_init(struct fuse_conn_info *info);
void b2fs_destroy(void *userdata);
int b2fs_getattr(const char *path, struct stat *statbuf);
int b2fs_readlink(const char *path, char *buf, size_t size);
int b2fs_opendir(const char *path, struct fuse_file_info *info);
int b2fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *info);
int b2fs_releasedir(const char *path, struct fuse_file_info *info);
int b2fs_mknod(const char *path, mode_t mode, dev_t rdev);
int b2fs_mkdir(const char *path, mode_t mode);
int b2fs_symlink(const char *from, const char *to);
int b2fs_unlink(const char *path);
int b2fs_rmdir(const char *path);
int b2fs_rename(const char *from, const char *to);
int b2fs_link(const char *from, const char *to);
int b2fs_chmod(const char *path, mode_t mode);
int b2fs_chown(const char *path, uid_t uid, gid_t gid);
int b2fs_truncate(const char *path, off_t size);
int b2fs_utime(const char *path, struct utimbuf *buf);
int b2fs_open(const char *path, struct fuse_file_info *info);
int b2fs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *info);
int b2fs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *info);
int b2fs_statfs(const char *path, struct statvfs *buf);
int b2fs_release(const char *path, struct fuse_file_info *info);
int b2fs_fsync(const char *path, int crap, struct fuse_file_info *info);
int b2fs_flush(const char *path, struct fuse_file_info *info);
int b2fs_access(const char *path, int mode);

// Network Functions.
size_t receive_string(void *data, size_t size, size_t nmembers, void *voidarg);

// Struct Initializers.
int init_file_entry(b2fs_file_entry_t *entry, int size);
void destroy_file_entry(void *voidarg);
void destroy_hash_entry(void *voidarg);

// Helper Functions.
int jsmn_iskey(const char *json, jsmntok_t *tok, const char *s);
char **split_path(char *path);
hash_t *make_path(char **path_pieces, hash_t *base);
void cache_auth(b2fs_state_t *b2_info);
int find_cached_auth(b2fs_state_t *b2_info);
int parse_config(b2_account_t *auth, char *config_file);
int attempt_authentication(b2_account_t *auth, b2fs_state_t *b2_info);
void find_tmpdir(char **out);
int intcmp(void *int_one, void *int_two);
void print_usage(int intentional);

/*----- Local Function Implementations -----*/

int main(int argc, char **argv) {
  int c, index, retval, exclusive = 0;
  b2_account_t account;
  b2fs_state_t b2_info;
  char *config = "b2fs.yml", *mount_point = NULL, *bucket = NULL;
  struct option long_options[] = {
    {"bucket", required_argument, 0, 'b'},
    {"config", required_argument, 0, 'c'},
    {"exclusive", no_argument, 0, 'e'},
    {"mount", required_argument, 0, 'm'},
    {0, 0, 0, 0}
  };

  // Create FUSE function mapping.
  struct fuse_operations mappings = {
    .getattr    = b2fs_getattr,
    .readlink   = b2fs_readlink,
    .opendir    = b2fs_opendir,
    .readdir    = b2fs_readdir,
    .releasedir = b2fs_releasedir,
    .mknod      = b2fs_mknod,
    .mkdir      = b2fs_mkdir,
    .unlink     = b2fs_unlink,
    .rmdir      = b2fs_rmdir,
    .rename     = b2fs_rename,
    .link       = b2fs_link,
    .chmod      = b2fs_chmod,
    .chown      = b2fs_chown,
    .truncate   = b2fs_truncate,
    .utime      = b2fs_utime,
    .open       = b2fs_open,
    .read       = b2fs_read,
    .write      = b2fs_write,
    .statfs     = b2fs_statfs,
    .release    = b2fs_release,
    .fsync      = b2fs_fsync,
    .flush      = b2fs_flush,
    .access     = b2fs_access
  };

  // Get CLI options.
  while ((c = getopt_long(argc, argv, "c:m:", long_options, &index)) != -1) {
    switch (c) {
      case 'b':
        bucket = optarg;
        break;
      case 'c':
        config = optarg;
        break;
      case 'e':
        exclusive = 1;
        break;
      case 'm':
        mount_point = optarg;
        break;
      default:
        print_usage(0);
    }
  }
  if (!mount_point || !bucket) {
    write_log(LEVEL_ERROR, "B2FS: At the very least, you must specify a mountpoint and bucket.\n");
    print_usage(0);
  } else if (strlen(bucket) > B2FS_SMALL_GENERIC_BUFFER - 1) {
    write_log(LEVEL_ERROR, "B2FS: Bucket name too long. Max length is %d.\n", B2FS_SMALL_GENERIC_BUFFER);
    print_usage(0);
  }
  curl_global_init(CURL_GLOBAL_DEFAULT);

  // Check if we have a cached API key.
  retval = find_cached_auth(&b2_info);

  // Get account information from the config file if not cached.
  if (retval && parse_config(&account, config)) {
    write_log(LEVEL_ERROR, "B2FS: Malformed config file.\n");
  }

  if (retval) {
    // Attempt to grab authentication token from B2.
    retval = attempt_authentication(&account, &b2_info);

    // Check response.
    if (retval == B2FS_NETWORK_ACCESS_ERROR) {
      write_log(LEVEL_ERROR, "B2FS: Authentication failed. Credentials are invalid.\n");
    } else if (retval == B2FS_NETWORK_API_ERROR) {
      write_log(LEVEL_ERROR, "B2FS: BackBlaze API has changed. B2FS will not work without an update.\n");
    } else if (retval == B2FS_NETWORK_INTERN_ERROR) {
      write_log(LEVEL_DEBUG, "B2FS: Internal error detected!!!! Failed to authenticate, reason: %s", b2_info.token);
      write_log(LEVEL_ERROR, "B2FS: Encountered an internal error while authenticating. Please try again.\n");
    } else if (retval == B2FS_GENERIC_NETWORK_ERROR) {
      write_log(LEVEL_DEBUG, "B2FS: cURL error encountered. Reason: %s\n", b2_info.token);
      write_log(LEVEL_ERROR, "B2FS: Network library error. Please try again.\n");
    } else if (retval == B2FS_GENERIC_ERROR) {
      write_log(LEVEL_ERROR, "B2FS: Failed to initialize network.\n");
    }
    if (retval != B2FS_SUCCESS) return EXIT_FAILURE;

    // Cache new auth info.
    cache_auth(&b2_info);
  }

  // We are authenticated and have a valid token. Start up FUSE.
  strcpy(b2_info.bucket, bucket);
  b2_info.exclusive = exclusive;
  argv[1] = mount_point;
  return fuse_main(2, argv, &mappings, &b2_info);
}

// TODO: Implement this function.
void *b2fs_init(struct fuse_conn_info *info) {
  b2fs_state_t *state = fuse_get_context()->private_data;

  // Initialize the filesystem cache.
  state->fs_cache = create_hash(destroy_hash_entry);
  if (!state->fs_cache) {
    write_log(LEVEL_ERROR, "B2FS: Could not allocate enough memory to start up.\n");
    fuse_exit(fuse_get_context()->fuse);
  }

  if (state->exclusive) {
    // The user has specified that we have exclusive access to the bucket.
    // Go ahead and cache all filenames ahead of time to decrease latency on later
    // calls.
    CURLcode res;
    CURL *curl = curl_easy_init();
    char urlbuf[B2FS_SMALL_GENERIC_BUFFER], start_filename[B2FS_SMALL_GENERIC_BUFFER];
    char auth[B2FS_SMALL_GENERIC_BUFFER], body[B2FS_SMALL_GENERIC_BUFFER];
    char *response = NULL;

    // Generate and set url for request.
    sprintf(state->api_url, "%s/%s", "b2api/v1/b2_list_file_names");
    strcpy(start_filename, "null");
    curl_easy_setopt(curl, CURLOPT_URL, urlbuf);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    // Set authorization header for request.
    sprintf(auth, "Authorization: %s", state->token);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Setup data callbacks.
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_string);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    // Loop until all files have been loaded.
    while (1) {
      // Set POST body.
      sprintf(body, "bucketId=%s&startFileName=%s&maxFileCount=1000", state->bucket, start_filename);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);

      // Perform request.
      if ((res = curl_easy_perform(curl)) == CURLE_OK) {
        long code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

        if (code == 200) {
          // Our request was accepted! Get ready to parse json response.
          int token_count = JSMN_ERROR_NOMEM;
          jsmn_parser parser;
          jsmntok_t *tokens = malloc(sizeof(jsmntok_t) * B2FS_MED_GENERIC_BUFFER);

          // Make sure enough memory is available, and parse response.
          for (int i = 1; token_count != JSMN_ERROR_NOMEM; i++) {
            token_count = jsmn_parse(&parser, response, strlen(response), tokens, B2FS_LARGE_GENERIC_BUFFER * i);
            if (token_count == JSMN_ERROR_NOMEM) {
              void *tmp = realloc(tokens, sizeof(jsmntok_t) * (B2FS_MED_GENERIC_BUFFER * (i + 1)));
              if (!tmp) {
                write_log(LEVEL_DEBUG, "B2FS: Failed to allocate enough tokens for initial fs caching...\n");
                write_log(LEVEL_ERROR, "B2FS: Could not allocate enough memory to start up.\n");
                if (tokens) free(tokens);
                destroy_hash(state->fs_cache);
                fuse_exit(fuse_get_context()->fuse);
              }
              tokens = tmp;
            } else if (token_count == JSMN_ERROR_INVAL || token_count == JSMN_ERROR_PART) {
              write_log(LEVEL_ERROR, "B2FS: B2 returned an invalid response during startup.\n");
              if (tokens) free(tokens);
              destroy_hash(state->fs_cache);
              fuse_exit(fuse_get_context()->fuse);
            }
          }

          // Zero start_filename to ensure null termination.
          memset(start_filename, 0, sizeof(char) * B2FS_SMALL_GENERIC_BUFFER);
          for (int i = 1; i < token_count; i++) {
            jsmntok_t *key = &tokens[i++], *value = &tokens[i];
            int len = value->end - value->start;

            if (jsmn_iskey(response, key, "files")) {
              for (int j = i + 1; j < i + value->size; j++) {
                jsmntok_t *file = &tokens[j];
                b2fs_hash_entry_t entry;
                char **path_pieces;
                long size;

                // Parse out file path pieces and file size.
                for (int k = j + 1; k < j + file->size; k++) {
                  jsmntok_t *obj_key = &tokens[k++], *obj_value = &tokens[k];
                  int obj_len = obj_value->end - obj_value->start;

                  if (jsmn_iskey(response, obj_key, "fileName")) {
                    char filename[B2FS_SMALL_GENERIC_BUFFER];
                    memset(filename, 0, sizeof(char) * B2FS_SMALL_GENERIC_BUFFER);
                    memcpy(filename, response + obj_value->start, obj_len);
                    path_pieces = split_path(filename);
                  } else if (jsmn_iskey(response, obj_key, "size")) {
                    size = strtol(response + obj_value->start, NULL, 10);
                  }
                }

                // Make all intermediate directories.
                hash_t *dir = make_path(path_pieces, state->fs_cache);
                
                // Initialize file entry.
                int num_chunks = ceil(ceil(size / (float) B2FS_CHUNK_SIZE) / (float) 8);
                entry.type = TYPE_FILE;
                init_file_entry(&entry.file, num_chunks);

                // Put it in the directory cache.
                hash_put(dir, path_pieces[0], &entry);

                // Clean up and prepare for next iteration.
                free(path_pieces);
                j += file->size;
              }
            } else if (jsmn_iskey(response, key, "nextFileName")) {
              memcpy(start_filename, response + value->start, len);
            } else {
              // We received an unknown key from B2. Log it, but try to keep going.
              LOG_KEY(response, key, "b2fs_init");
            }

            // Prepare for next iteration.
            i += value->size;
          }
        }
      }
    }
  }

  return NULL;
}

// TODO: Implement this function.
void b2fs_destroy(void *userdata) {

}

// TODO: Implement this function.
int b2fs_getattr(const char *path, struct stat *statbuf) {
  return -ENOTSUP;
}

int b2fs_readlink(const char *path, char *buf, size_t size) {
  (void) path;
  (void) buf;
  (void) size;
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_opendir(const char *path, struct fuse_file_info *info) {
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *info) {
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_releasedir(const char *path, struct fuse_file_info *info) {
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_mknod(const char *path, mode_t mode, dev_t rdev) {
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_mkdir(const char *path, mode_t mode) {
  return -ENOTSUP;
}

int b2fs_symlink(const char *from, const char *to) {
  (void) from;
  (void) to;
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_unlink(const char *path) {
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_rmdir(const char *path) {
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_rename(const char *from, const char *to) {
  return -ENOTSUP;
}

int b2fs_link(const char *from, const char *to) {
  (void) from;
  (void) to;
  return -ENOTSUP;
}

int b2fs_chmod(const char *path, mode_t mode) {
  (void) path;
  (void) mode;
  return -ENOTSUP;
}

int b2fs_chown(const char *path, uid_t uid, gid_t gid) {
  (void) path;
  (void) uid;
  (void) gid;
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_truncate(const char *path, off_t size) {
  return -ENOTSUP;
}

int b2fs_utime(const char *path, struct utimbuf *buf) {
  (void) path;
  (void) buf;
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_open(const char *path, struct fuse_file_info *info) {
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *info) {
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *info) {
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_statfs(const char *path, struct statvfs *buf) {
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_release(const char *path, struct fuse_file_info *info) {
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_fsync(const char *path, int crap, struct fuse_file_info *info) {
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_flush(const char *path, struct fuse_file_info *info) {
  return -ENOTSUP;
}

int b2fs_access(const char *path, int mode) {
  (void) path;
  (void) mode;
  return -ENOTSUP;
}

size_t receive_string(void *data, size_t size, size_t nmembers, void *voidarg) {
  char *recvbuf = malloc(sizeof(char) * ((size * nmembers) + 1));

  if (recvbuf) {
    char **output = voidarg;
    memcpy(recvbuf, data, size * nmembers);
    *(recvbuf + (size * nmembers)) = '\0';
    *output = recvbuf;
    return size * nmembers;
  } else {
    return 0;
  }
}


int init_file_entry(b2fs_file_entry_t *entry, int size) {
  if (!entry) return B2FS_INVAL;

  memset(entry, 0, sizeof(b2fs_file_entry_t));
  entry->chunkmap = create_bitmap(size ? size : B2FS_INIT_CHUNK_NUM);
  entry->chunks = create_keytree(free, free, intcmp, sizeof(int), sizeof(b2fs_file_chunk_t));
  if (!entry->chunkmap || !entry->chunks) {
    if (entry->chunkmap) free(entry->chunkmap);
    if (entry->chunks) free(entry->chunks);
    return B2FS_NOMEM;
  }

  return B2FS_SUCCESS;
}

void destroy_file_entry(void *voidarg) {
  b2fs_file_entry_t *entry = voidarg;
  keytree_destroy(entry->chunks);
  destroy_bitmap(entry->chunkmap);
  if (entry->dynamic) free(entry);
}

void destroy_hash_entry(void *voidarg) {
  b2fs_hash_entry_t *entry = voidarg;
  
  // Identify entry type and destroy.
  if (entry->type == TYPE_DIRECTORY) destroy_hash(entry->directory);
  else destroy_file_entry(&entry->file);
}

int jsmn_iskey(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type != JSMN_STRING) return 0;
  if (((int) strlen(s)) != (tok->end - tok->start)) return 0;
  if (strncmp(json + tok->start, s, tok->end - tok->start)) return 0;
  return 1;
}

char **split_path(char *path) {
  char **parts = malloc(sizeof(char *) * B2FS_SMALL_GENERIC_BUFFER), **strtok_ptr;
  int size = B2FS_SMALL_GENERIC_BUFFER, counter = 0;

  // Iterate across string, reallocating as we go, and store token pointers.
  for (char *current = strtok_r(path, "/", strtok_ptr); current; current = strtok_r(NULL, "/", strtok_ptr)) {
    if (counter == size - 1) {
      void *tmp = realloc(parts, size *= 2);
      if (!tmp) {
        free(parts);
        return NULL;
      }
      parts = tmp;
    }
    parts[counter++] = current;
  }
  parts[counter++] = NULL;

  return parts;
}

hash_t *make_path(char **path_pieces, hash_t *base) {
  hash_t *current = base;
  int i = 0;
  
  // Iterate across path pieces and create all intermediate directories.
  for (char *piece = path_pieces[i++]; path_pieces[i + 1]; piece = path_pieces[i++]) {
    b2fs_hash_entry_t *entry = hash_get(current, piece);

    if (!entry) {
      // Create a new hash entry of type directory.
      b2fs_hash_entry_t new_entry;
      new_entry.type = TYPE_DIRECTORY;
      new_entry.directory = create_hash(destroy_hash_entry);

      // Put it in the previous directory.
      hash_put(current, piece, &new_entry);
      entry = hash_get(current, piece);
    } else if (entry->type != TYPE_DIRECTORY) {
      // An intermediate piece was not a directory. Give up and return.
      return NULL;
    }

    current = entry->directory;
  }

  // Move final piece up to front of array for ease of access.
  path_pieces[0] = path_pieces[i];

  // Return the directory containing the file.
  return current;
}

void cache_auth(b2fs_state_t *b2_info) {
  char *tmpdir, path[B2FS_SMALL_GENERIC_BUFFER];

  // Locate system tmpdir if possible.
  find_tmpdir(&tmpdir);
  if (!tmpdir) return;

  // Open cache file.
  sprintf(path, "%s/b2fs_cache.txt", tmpdir);
  FILE *cache_out = fopen(path, "w+");

  // Write it out.
  if (cache_out) {
    fprintf(cache_out, "%s\n%s\n%s", b2_info->token, b2_info->api_url, b2_info->down_url);
    fclose(cache_out);
  }
}

int find_cached_auth(b2fs_state_t *b2_info) {
  char *tmpdir, path[B2FS_SMALL_GENERIC_BUFFER];
  memset(b2_info, 0, sizeof(b2fs_state_t));

  // Locate system tmpdir if possible.
  find_tmpdir(&tmpdir);
  if (!tmpdir) return B2FS_GENERIC_ERROR;

  // Open cache file.
  sprintf(path, "%s/b2fs_cache.txt", tmpdir);
  FILE *cache_in = fopen(path, "r");

  // Read the cached info in.
  if (cache_in) {
    int success;
    fscanf(cache_in, "%s\n%s\n%s", b2_info->token, b2_info->api_url, b2_info->down_url);
    success = strlen(b2_info->token) && strlen(b2_info->api_url) && strlen(b2_info->down_url);
    return success ? B2FS_SUCCESS : B2FS_GENERIC_ERROR;
  } else {
    return B2FS_GENERIC_ERROR;
  }
}

int parse_config(b2_account_t *auth, char *config_file) {
  FILE *config = fopen(config_file, "r");
  char keybuf[B2FS_SMALL_GENERIC_BUFFER], valbuf[B2FS_SMALL_GENERIC_BUFFER];
  memset(auth, 0, sizeof(b2_account_t));

  if (config) {
    for (int i = 0; i < 2; i++) {
      fscanf(config, "%s %s\n", keybuf, valbuf);

      if (!strcmp(keybuf, "account_id:")) {
        strcpy(auth->account_id, valbuf);
      } else if (!strcmp(keybuf, "app_key:")) {
        strcpy(auth->app_key, valbuf);
      } else {
        write_log(LEVEL_ERROR, "B2FS: Malformed config file.\n");
      }
    }
    return B2FS_SUCCESS;
  } else {
    return B2FS_GENERIC_ERROR;
  }
}

int attempt_authentication(b2_account_t *auth, b2fs_state_t *b2_info) {
  CURL *curl;
  CURLcode res;

  curl = curl_easy_init();
  if (curl) {
    char *url = "https://api.backblaze.com/b2api/v1/b2_authorize_account";
    char conversionbuf[B2FS_SMALL_GENERIC_BUFFER], based[B2FS_SMALL_GENERIC_BUFFER], final[B2FS_SMALL_GENERIC_BUFFER];
    char *tmp = based, *data = NULL;

    // Set URL for request.
    curl_easy_setopt(curl, CURLOPT_URL, url);

    // Create token to send for authentication.
    base64_encodestate state;
    base64_init_encodestate(&state);
    sprintf(conversionbuf, "%s:%s", auth->account_id, auth->app_key);
    tmp += base64_encode_block(conversionbuf, strlen(conversionbuf), tmp, &state);
    tmp += base64_encode_blockend(tmp, &state);
    *(--tmp) = '\0';
    sprintf(final, "Authorization: Basic %s", based);

    // Setup custom headers.
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, final);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Setup data callback.
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_string);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);

    // Attempt authentication.
    if ((res = curl_easy_perform(curl)) == CURLE_OK) {
      // No cURL errors occured, time to check for HTTP errors...
      long code;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
      curl_easy_cleanup(curl);

      if (code == 200) {
        int token_count = 0;
        jsmn_parser parser;
        jsmntok_t tokens[B2FS_SMALL_GENERIC_BUFFER];

        // Our authentication request went through. Time to JSON parse.
        jsmn_init(&parser);
        token_count = jsmn_parse(&parser, data, strlen(data), tokens, B2FS_SMALL_GENERIC_BUFFER);
        if (token_count == JSMN_ERROR_NOMEM || tokens[0].type != JSMN_OBJECT) {
          free(data);
          return B2FS_NETWORK_API_ERROR;
        }

        // Iterate over returned tokens and extract the needed info.
        memset(b2_info, 0, sizeof(b2fs_state_t));
        for (int i = 1; i < token_count; i++) {
          jsmntok_t *key = &tokens[i++], *value = &tokens[i];
          int len = value->end - value->start;

          if (jsmn_iskey(data, key, "authorizationToken")) {
            memcpy(b2_info->token, data + value->start, len);
          } else if (jsmn_iskey(data, key, "apiUrl")) {
            memcpy(b2_info->api_url, data + value->start, len);
          } else if (jsmn_iskey(data, key, "downloadUrl")) {
            memcpy(b2_info->down_url, data + value->start, len);
          } else if (!jsmn_iskey(data, key, "accountId")) {
            LOG_KEY(data, key, "authentication");
          }
        }
        free(data);

        // Validate and return!
        if (strlen(b2_info->token) && strlen(b2_info->api_url) && strlen(b2_info->down_url)) {
          return B2FS_SUCCESS;
        } else {
          return B2FS_NETWORK_API_ERROR;
        }
      } else if (code == 401) {
        // Our authentication request was rejected due to bad auth info.
        free(data);
        return B2FS_NETWORK_ACCESS_ERROR;
      } else {
        // Request was badly formatted. Denotes an internal error.
        strncpy(b2_info->token, data, B2FS_TOKEN_LEN - 1);
        b2_info->token[B2FS_TOKEN_LEN - 1] = '\0';
        free(data);
        return B2FS_NETWORK_INTERN_ERROR;
      }
      return B2FS_SUCCESS;
    } else {
      // cURL error encountered. Don't know enough about this to predict why.
      // FIXME: Maybe add more detailed error handling here.
      strncpy(b2_info->token, curl_easy_strerror(res), B2FS_TOKEN_LEN - 1);
      b2_info->token[B2FS_TOKEN_LEN - 1] = '\0';
      curl_easy_cleanup(curl);
      return B2FS_GENERIC_NETWORK_ERROR;
    }
  } else {
    curl_easy_cleanup(curl);
    return B2FS_GENERIC_ERROR;
  }
}

void find_tmpdir(char **out) {
  static char *fallback = "/tmp";
  char *tmpdir = NULL;

  *out = NULL;
  tmpdir = getenv("TMPDIR");
  if (tmpdir && !*out) *out = tmpdir;
  tmpdir = getenv("TMP");
  if (tmpdir && !*out) *out = tmpdir;
  tmpdir = getenv("TEMP");
  if (tmpdir && !*out) *out = tmpdir;
  tmpdir = getenv("TEMPDIR");
  if (tmpdir && !*out) *out = tmpdir;

  if (!*out && !access("/tmp", R_OK)) *out = fallback;
}

int intcmp(void *int_one, void *int_two) {
  return *((int *) int_one) - *((int *) int_two);
}

void print_usage(int intentional) {
  puts("./b2fs <--config | YAML file to read config from> <--mount | Mount point>");
  exit(intentional ? EXIT_SUCCESS : EXIT_FAILURE);
}
