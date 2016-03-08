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
#define B2FS_FS_NOTDIR_ERROR -0x0200
#define B2FS_FS_NOENT_ERROR -0x0201

// Numerical Constants.
#define B2FS_ACCOUNT_ID_LEN 16
#define B2FS_APP_KEY_LEN 64
#define B2FS_TOKEN_LEN 128
#define B2FS_MICRO_GENERIC_BUFFER 64
#define B2FS_SMALL_GENERIC_BUFFER 256
#define B2FS_MED_GENERIC_BUFFER 1024
#define B2FS_LARGE_GENERIC_BUFFER 4096
#define B2FS_CHUNK_SIZE (1024 * 1024 * 4)

#define FUSE_USE_VERSION 30

#define ROOT_UID 0
#define ROOT_GID 0

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
#include "structures/array.h"
#include "structures/bitmap.h"
#include "structures/stack.h"
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

typedef enum b2fs_delete_policy {
  POLICY_INVAL,
  POLICY_HIDE,
  POLICY_DELETE_ONE,
  POLICY_DELETE_ALL
} b2fs_delete_policy_t;

typedef enum b2fs_entry_type {
  TYPE_DIRECTORY,
  TYPE_FILE
} b2fs_entry_type_t;

typedef struct b2fs_string {
  char *str;
  unsigned int len, ptr;
} b2fs_string_t;

typedef struct b2fs_config {
  char account_id[B2FS_ACCOUNT_ID_LEN];
  char app_key[B2FS_APP_KEY_LEN];
  char bucket_id[B2FS_SMALL_GENERIC_BUFFER];
  char mount_point[B2FS_SMALL_GENERIC_BUFFER];
  b2fs_delete_policy_t policy;
} b2fs_config_t;

typedef struct b2fs_file_version {
  char version_id[B2FS_SMALL_GENERIC_BUFFER];
  char action[B2FS_MICRO_GENERIC_BUFFER];
  size_t size;
} b2fs_file_version_t;

typedef struct b2fs_file_chunk {
  int chunk_num, size;
  char data[B2FS_CHUNK_SIZE];
} b2fs_file_chunk_t;

typedef struct b2fs_file_entry {
  bitmap_t *chunkmap;
  keytree_t *chunks, *versions;
  int readers, writers;
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
  b2fs_delete_policy_t policy;
  hash_t *fs_cache;
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
int attempt_authentication(b2fs_config_t *config, b2fs_state_t *b2_info);

// Struct Initializers.
int init_file_entry(b2fs_file_entry_t *entry);
void destroy_file_entry(void *voidarg);
void destroy_hash_entry(void *voidarg);

// Filesystem Helpers.
char **split_path(char *path);
hash_t *make_path(char **path_pieces, hash_t *base);
int find_path(char *path, hash_t *base, b2fs_hash_entry_t *buf);
int internal_make(const char *path, hash_t *base, b2fs_entry_type_t type);

// Generic Helper Functions.
int jsmn_iskey(const char *json, jsmntok_t *tok, const char *s);
void cache_auth(b2fs_state_t *b2_info);
int find_cached_auth(b2fs_state_t *b2_info);
int parse_config(b2fs_config_t *config, char *config_filename);
void find_tmpdir(char **out);
int intcmp(void *int_one, void *int_two);
int rev_intcmp(void *int_one, void *int_two);
void print_usage(int intentional);

/*----- Local Function Implementations -----*/

int main(int argc, char **argv) {
  int c, index, retval, config_requested = 0;
  b2fs_config_t config;
  b2fs_state_t b2_info;
  char *config_file = "b2fs.yml", *mount_point = NULL;
  char *debug = "-d", *single_threaded = "-s";
  struct option long_options[] = {
    {"account-id", required_argument, 0, 'a'},
    {"bucket", required_argument, 0, 'b'},
    {"config", required_argument, 0, 'c'},
    {"debug", no_argument, 0, 'd'},
    {"app-key", required_argument, 0, 'k'},
    {"mount", required_argument, 0, 'm'},
    {"delete-policy", required_argument, 0, 'p'},
    {"single-threaded", no_argument, 0, 's'},
    {0, 0, 0, 0}
  };
  array_t *fuse_options = create_array(sizeof(char *), NULL);
  memset(&config, 0, sizeof(b2fs_config_t));

  // Create FUSE function mapping.
  struct fuse_operations mappings = {
    .init       = b2fs_init,
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
  while ((c = getopt_long(argc, argv, "b:c:dem:p:s", long_options, &index)) != -1) {
    switch (c) {
      case 'a':
        if (strlen(optarg) > B2FS_ACCOUNT_ID_LEN - 1) {
          write_log(LEVEL_ERROR, "B2FS: Account id too long. Max length is %d.\n", B2FS_ACCOUNT_ID_LEN);
          print_usage(0);
        }
        strcpy(config.account_id, optarg);
        break;
      case 'b': 
        if (strlen(optarg) > B2FS_SMALL_GENERIC_BUFFER - 1) {
          write_log(LEVEL_ERROR, "B2FS: Bucket name too long. Max length is %d.\n", B2FS_SMALL_GENERIC_BUFFER);
          print_usage(0);
        }
        strcpy(config.bucket_id, optarg);
        break;
      case 'c':
        config_requested = 1;
        config_file = optarg;
        break;
      case 'd':
        array_push(fuse_options, &debug);
        break;
      case 'k':
        if (strlen(optarg) > B2FS_APP_KEY_LEN) {
          write_log(LEVEL_ERROR, "B2FS: App key too long. Max length is %d.\n", B2FS_APP_KEY_LEN);
          print_usage(0);
        }
        strcpy(config.app_key, optarg);
        break;
      case 'm':
        mount_point = optarg;
        break;
      case 'p':
        if (!strcmp("hide", optarg)) config.policy = POLICY_HIDE;
        else if (!strcmp("delete", optarg)) config.policy = POLICY_DELETE_ONE;
        else if (!strcmp("delete_all", optarg)) config.policy = POLICY_DELETE_ALL;
        else print_usage(0);
        break;
      case 's':
        array_push(fuse_options, &single_threaded);
        break;
      default:
        print_usage(0);
    }
  }

  // Initialize cURL.
  curl_global_init(CURL_GLOBAL_DEFAULT);

  // Check if we have a cached API key.
  retval = find_cached_auth(&b2_info);

  // Get account information from the config file if not cached.
  if (parse_config(&config, config_file)) {
    write_log(LEVEL_ERROR, "B2FS: Malformed config file.\n");
    exit(EXIT_FAILURE);
  }

  // Validate given options.
  if (config.policy == POLICY_INVAL) config.policy = POLICY_HIDE;
  if (!mount_point && !strlen(config.mount_point)) {
    write_log(LEVEL_ERROR, "B2FS: You must specify a mount point.\n");
    print_usage(0);
  } else if (!mount_point) {
    mount_point = config.mount_point;
  }

  if (retval) {
    // Attempt to grab authentication token from B2.
    retval = attempt_authentication(&config, &b2_info);

    // Check response.
    switch (retval) {
      case B2FS_NETWORK_ACCESS_ERROR:
        write_log(LEVEL_ERROR, "B2FS: Authentication failed. Credentials are invalid.\n");
        break;
      case B2FS_NETWORK_API_ERROR:
        write_log(LEVEL_ERROR, "B2FS: BackBlaze API has changed. B2FS will not work without an update.\n");
        break;
      case B2FS_NETWORK_INTERN_ERROR:
        write_log(LEVEL_DEBUG, "B2FS: Internal error detected!!!! Failed to authenticate, reason: %s", b2_info.token);
        write_log(LEVEL_ERROR, "B2FS: Encountered an internal error while authenticating. Please try again.\n");
        break;
      case B2FS_GENERIC_NETWORK_ERROR:
        write_log(LEVEL_DEBUG, "B2FS: cURL error encountered. Reason: %s\n", b2_info.token);
        write_log(LEVEL_ERROR, "B2FS: Network library error. Please try again.\n");
        break;
      case B2FS_GENERIC_ERROR:
        write_log(LEVEL_ERROR, "B2FS: Failed to initialize network.\n");
    }
    if (retval != B2FS_SUCCESS) return EXIT_FAILURE;

    // Cache new auth info.
    cache_auth(&b2_info);
  }

  // We are authenticated and have a valid token. Start up FUSE.
  strcpy(b2_info.bucket, config.bucket_id);

  // Get CLI arguments ready for FUSE.
  argv[1] = mount_point;
  for (int i = 0; i < array_count(fuse_options); i++) {
    char *option;
    array_retrieve(fuse_options, i, &option);
    argv[i + 2] = option;
  }

  // Start FUSE.
  return fuse_main(array_count(fuse_options) + 2, argv, &mappings, &b2_info);
}

void *b2fs_init(struct fuse_conn_info *info) {
  (void) info;
  b2fs_state_t *state = fuse_get_context()->private_data;

  // Initialize the filesystem cache.
  state->fs_cache = create_hash(sizeof(b2fs_hash_entry_t), destroy_hash_entry);
  if (!state->fs_cache) {
    write_log(LEVEL_ERROR, "B2FS: Could not allocate enough memory to start up.\n");
    hash_destroy(state->fs_cache);
    fuse_exit(fuse_get_context()->fuse);
  }

  // B2FS currently expects to have exclusive access to the bucket.
  // Go ahead and cache all filenames ahead of time to decrease latency on later
  // calls.
  CURLcode res;
  CURL *curl = curl_easy_init();
  char urlbuf[B2FS_SMALL_GENERIC_BUFFER], start_filename[B2FS_SMALL_GENERIC_BUFFER];
  char start_fileid[B2FS_SMALL_GENERIC_BUFFER], auth[B2FS_SMALL_GENERIC_BUFFER];
  char body[B2FS_SMALL_GENERIC_BUFFER];
  b2fs_string_t response;
  memset(&response, 0, sizeof(b2fs_string_t));

  // Generate and set url for request.
  sprintf(urlbuf, "%s/%s", state->api_url, "b2api/v1/b2_list_file_versions");
  memset(start_filename, 0, B2FS_SMALL_GENERIC_BUFFER);
  memset(start_fileid, 0, B2FS_SMALL_GENERIC_BUFFER);
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
  while (strcmp(start_filename, "null") && strcmp(start_fileid, "null")) {
    // Set POST body.
    if (strlen(start_filename) || strlen(start_fileid)) {
      // Quick sanity checking.
      assert(strlen(start_filename) && strlen(start_fileid));

      // I hate putting single calls on multiple lines, but this is otherwise too long.
      sprintf(body,
          "{\"bucketId\":\"%s\",\"startFileName\":\"%s\",\"startFileId\":\"%s\",\"maxFileCount\":1000}",
          state->bucket, start_filename, start_fileid);
    } else {
      sprintf(body, "{\"bucketId\":\"%s\",\"maxFileCount\":1000}", state->bucket);
    }
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
        for (int i = 1; token_count == JSMN_ERROR_NOMEM; i++) {
          memset(&parser, 0, sizeof(jsmn_parser));
          token_count = jsmn_parse(&parser, response.str, strlen(response.str), tokens, B2FS_MED_GENERIC_BUFFER * i);
          if (token_count == JSMN_ERROR_NOMEM) {
            void *tmp = realloc(tokens, sizeof(jsmntok_t) * (B2FS_MED_GENERIC_BUFFER * (i + 1)));
            if (!tmp) {
              write_log(LEVEL_DEBUG, "B2FS: Failed to allocate enough tokens for initial fs caching...\n");
              write_log(LEVEL_ERROR, "B2FS: Could not allocate enough memory to start up.\n");
              if (tokens) free(tokens);
              hash_destroy(state->fs_cache);
              curl_slist_free_all(headers);
              curl_easy_cleanup(curl);
              fuse_exit(fuse_get_context()->fuse);
            }
            tokens = tmp;
          } else if (token_count == JSMN_ERROR_INVAL || token_count == JSMN_ERROR_PART) {
            write_log(LEVEL_ERROR, "B2FS: B2 returned an invalid response during startup.\n");
            if (tokens) free(tokens);
            hash_destroy(state->fs_cache);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            fuse_exit(fuse_get_context()->fuse);
          }
        }

        // Zero start_filename and start_fileid to ensure null termination.
        memset(start_filename, 0, sizeof(char) * B2FS_SMALL_GENERIC_BUFFER);
        memset(start_fileid, 0, sizeof(char) * B2FS_SMALL_GENERIC_BUFFER);
        for (int i = 1; i < token_count; i++) {
          jsmntok_t *key = &tokens[i++], *value = &tokens[i++];
          int len = value->end - value->start, token_index = i;

          if (jsmn_iskey(response.str, key, "files")) {
            for (int j = 0; j < value->size; j++) {
              jsmntok_t *file = &tokens[token_index++];
              b2fs_hash_entry_t entry;
              b2fs_file_version_t version;
              char **path_pieces, filename[B2FS_SMALL_GENERIC_BUFFER];
              long size, timestamp;

              // Parse out file path pieces and file size.
              for (int k = 0; k < file->size; k++) {
                jsmntok_t *obj_key = &tokens[token_index++], *obj_value = &tokens[token_index++];
                int obj_len = obj_value->end - obj_value->start;

                if (jsmn_iskey(response.str, obj_key, "fileName")) {
                  memset(filename, 0, sizeof(char) * B2FS_SMALL_GENERIC_BUFFER);
                  memcpy(filename, response.str + obj_value->start, obj_len);
                  path_pieces = split_path(filename);
                } else if (jsmn_iskey(response.str, obj_key, "size")) {
                  size = strtol(response.str + obj_value->start, NULL, 10);
                } else if (jsmn_iskey(response.str, obj_key, "uploadTimestamp")) {
                  timestamp = strtol(response.str + obj_value->start, NULL, 10);
                } else if (jsmn_iskey(response.str, obj_key, "fileId")) {
                  memset(version.version_id, 0, sizeof(char) * B2FS_SMALL_GENERIC_BUFFER);
                  memcpy(version.version_id, response.str + obj_value->start, obj_len);
                } else if (jsmn_iskey(response.str, obj_key, "action")) {
                  memset(version.action, 0, sizeof(char) * B2FS_MICRO_GENERIC_BUFFER);
                  memcpy(version.action, response.str + obj_value->start, obj_len);
                }
              }

              // Make all intermediate directories.
              hash_t *dir = make_path(path_pieces, state->fs_cache);

              if (hash_get(dir, path_pieces[0], &entry) != HASH_SUCCESS) {
                // Hash entry does not exist. This is the first time we've seen this file.
                entry.type = TYPE_FILE;
                init_file_entry(&entry.file);
                hash_put(dir, path_pieces[0], &entry);
              }
              assert(strlen(version.action) > 0 && strlen(version.version_id) > 0);
              version.size = size;
              keytree_insert(entry.file.versions, &timestamp, &version);

              // Clean up and prepare for next iteration.
              free(path_pieces);
            }

            // Back up the token index for the outer loop.
          } else if (jsmn_iskey(response.str, key, "nextFileName")) {
            memcpy(start_filename, response.str + value->start, len);
          } else if (jsmn_iskey(response.str, key, "nextFileId")) {
            memcpy(start_fileid, response.str + value->start, len);
          } else {
            // We received an unknown key from B2. Log it, but try to keep going.
            LOG_KEY(response.str, key, "b2fs_init");
          }

          // Prepare for next iteration.
          i = --token_index;
        }

        // Clear the response string to prepare for the next iteration.
        free(response.str);
        response.str = NULL;
        response.ptr = 0;
      } else {
        // TODO: Most likely reason this would happen, assuming the code is correct, is due to an expired token. Need to add
        // logic here to attempt a re-authentication.
        write_log(LEVEL_DEBUG, "B2FS: B2 returned error code %ld with message: %s\n", code, response.str);
        write_log(LEVEL_ERROR, "B2FS: B2 returned an error during startup. This is most likely a bug. Go make a report.\n");
        hash_destroy(state->fs_cache);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        fuse_exit(fuse_get_context()->fuse);
      }
    } else {
      write_log(LEVEL_DEBUG, "B2FS: cURL failed with error %s during initial caching.\n", curl_easy_strerror(res));
      hash_destroy(state->fs_cache);
      curl_slist_free_all(headers);
      curl_easy_cleanup(curl);
      fuse_exit(fuse_get_context()->fuse);
    }
  }

  // Cleanup cURL resources.
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  return state;
}

// TODO: Implement this function.
void b2fs_destroy(void *userdata) {
  (void) userdata;
}

// TODO: Implement this function.
int b2fs_getattr(const char *path, struct stat *statbuf) {
  b2fs_state_t *state = fuse_get_context()->private_data;

  int retval;
  b2fs_hash_entry_t entry;
  b2fs_file_version_t version;
  if (strcmp(path, "/")) {
    char *path_copy = malloc(sizeof(char) * (strlen(path) + 1));
    strcpy(path_copy, path);
    retval = find_path(path_copy, state->fs_cache, &entry);
    free(path_copy);
  } else {
    entry.type = TYPE_DIRECTORY;
    retval = B2FS_SUCCESS;
  }

  // Check if entry was found.
  if (retval == B2FS_SUCCESS) {
    // Entry exists. Initialize and set values for stat struct.
    memset(statbuf, 0, sizeof(struct stat));

    // Set file/directory flags.
    if (entry.type == TYPE_FILE) statbuf->st_mode |= S_IFREG;
    else statbuf->st_mode |= S_IFDIR;

    // Set read-write-execute permissions for everyone.
    statbuf->st_mode |= S_IRWXU | S_IRWXG | S_IRWXO;

    // Set owner details.
    statbuf->st_uid = ROOT_UID;
    statbuf->st_gid = ROOT_GID;

    // Get info for most recent file version.
    size_t timestamp;
    if (entry.type == TYPE_FILE) {
      keytree_iterator_t *it = keytree_iterate_start(entry.file.versions, NULL);
      keytree_iterate_next(it, &timestamp, &version);
      keytree_iterate_stop(it);
    }

    // Set other unsupported fields to sane defaults.
    statbuf->st_nlink = 1;
    statbuf->st_blksize = 512;
    statbuf->st_blocks = entry.type == TYPE_FILE ? ceil(version.size / (float) 512) : 1;

    // Set file access dates.
    // FIXME: I'm assuming these should be UNIX timestamps, but POSIX seems to be a little unsure.
    // Should probably come up with a better default than 0 for directories. Maybe when I'm feeling
    // less lazy I could scan across the contents to find the lowest timestamp.
    if (entry.type == TYPE_FILE) {
      statbuf->st_atime = timestamp;
      statbuf->st_mtime = timestamp;
      statbuf->st_ctime = timestamp;
    }

    // FIXME: Should directories return size 0?
    if (entry.type == TYPE_FILE) statbuf->st_size = version.size;

    return B2FS_SUCCESS;
  } else {
    // Entry does not exist. Indicate this.
    return -ENOENT;
  }
}

// TODO: Maybe someday support links.
int b2fs_readlink(const char *path, char *buf, size_t size) {
  (void) path;
  (void) buf;
  (void) size;
  return -ENOTSUP;
}

// FIXME: Doesn't seem like this function actually needs to do very much in our case.
// Currently only performs validation that the path given is, indeed, a directory.
int b2fs_opendir(const char *path, struct fuse_file_info *info) {
  (void) info;
  b2fs_state_t *state = fuse_get_context()->private_data;

  // If the user is requesting to open /, automatically return success.
  if (strcmp(path, "/")) {
    // Get the entry from the cache.
    b2fs_hash_entry_t entry;
    char *path_copy = malloc(sizeof(char) * (strlen(path) + 1));
    strcpy(path_copy, path);
    int retval = find_path(path_copy, state->fs_cache, &entry);
    free(path_copy);

    // Perform validation and return.
    if (retval == B2FS_SUCCESS) return entry.type == TYPE_DIRECTORY ? B2FS_SUCCESS : -ENOTDIR;
    else return -ENOENT;
  } else {
    return B2FS_SUCCESS;
  }
}

int b2fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *info) {
  (void) offset;
  (void) info;
  b2fs_state_t *state = fuse_get_context()->private_data;

  hash_t *directory;
  if (strcmp(path, "/")) {
    // Find requested directory.
    b2fs_hash_entry_t entry;
    char *path_copy = malloc(sizeof(char) * (strlen(path) + 1));
    strcpy(path_copy, path);
    int retval = find_path(path_copy, state->fs_cache, &entry);
    free(path_copy);

    // Should be impossible for find_path to return an error if this code is correct.
    assert(retval == B2FS_SUCCESS);

    // I'm assuming that all necessary validation for the path is done by b2fs_opendir, and that we
    // already know that the given path exists and is a directory.
    directory = entry.directory;
  } else {
    // User is asking to open /. Just use fs_cache.
    directory = state->fs_cache;
  }

  // Iterate across the keys and pass them to the filler function.
  int num_entries;
  char **keys = hash_keys(directory, &num_entries);
  for (int i = 0; i < num_entries; i++) filler(buf, keys[i], NULL, 0);
  free(keys);

  return B2FS_SUCCESS;
}

// There isn't really anything to do in this function. Opendir doesn't maintain any state, so, for now
// this just returns success.
int b2fs_releasedir(const char *path, struct fuse_file_info *info) {
  (void) path;
  (void) info;
  return B2FS_SUCCESS;
}

// Function only supports creating a regular file. Also, currently ignores permissions.
// B2 doesn't support adding empty files, so this only modifies the local cache.
// Local filesystem will report that the file exists, but if nothing is written to it
// before the filesystem is shut down, it will not be persisted.
int b2fs_mknod(const char *path, mode_t mode, dev_t rdev) {
  (void) rdev;
  b2fs_state_t *state = fuse_get_context()->private_data;

  if (S_ISREG(mode)) {
    // We're making a regular file.
    return internal_make(path, state->fs_cache, TYPE_FILE);
  } else {
    // We're being asked to create something other than a regular file. Not currently supported.
    return -ENOTSUP;
  }
}

// Function creates a new directory. Currently ignores permissions.
// B2 doesn't support adding empty directories, so this only modifies the local cache.
// Local filesystem will report that the directory exists, but if nothing is added to
// it before the filesystem is shut down, it will not be persisted.
int b2fs_mkdir(const char *path, mode_t mode) {
  (void) mode;
  b2fs_state_t *state = fuse_get_context()->private_data;

  // Make the directory.
  return internal_make(path, state->fs_cache, TYPE_DIRECTORY);
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

// B2FS doesn't currently support permissions, so this just checks that the
// entry in question actually exists and returns success.
int b2fs_access(const char *path, int mode) {
  (void) mode;
  b2fs_state_t *state = fuse_get_context()->private_data;

  if (strcmp(path, "/")) {
    b2fs_hash_entry_t entry;
    char *path_copy = malloc(sizeof(char) * (strlen(path) + 1));
    strcpy(path_copy, path);
    int retval = find_path(path_copy, state->fs_cache, &entry);
    free(path_copy);

    // Error handling and return.
    if (retval == B2FS_FS_NOENT_ERROR) return -ENOENT;
    else if (retval == B2FS_FS_NOTDIR_ERROR) return -ENOTDIR;
    else return retval;
  } else {
    // User is trying to access root directory. Always exists.
    return B2FS_SUCCESS;
  }
}

size_t receive_string(void *data, size_t size, size_t nmembers, void *voidarg) {
  b2fs_string_t *output = voidarg;

  // Check for resize.
  if (output->len < (size * nmembers) + output->ptr + 1) {
    unsigned int power = 1;
    while (power <= (size * nmembers) + output->ptr + 1) power <<= 1;
    void *tmp = realloc(output->str, power);
    if (!tmp) return 0;
    output->str = tmp;
  }

  memcpy(output->str + output->ptr, data, size * nmembers);
  output->str[output->ptr + (size * nmembers)] = '\0';
  output->ptr += size *nmembers;
  return size * nmembers;
}

int attempt_authentication(b2fs_config_t *config, b2fs_state_t *b2_info) {
  CURL *curl;
  CURLcode res;

  curl = curl_easy_init();
  if (curl) {
    char *url = "https://api.backblaze.com/b2api/v1/b2_authorize_account";
    char conversionbuf[B2FS_SMALL_GENERIC_BUFFER], based[B2FS_SMALL_GENERIC_BUFFER], final[B2FS_SMALL_GENERIC_BUFFER];
    char *tmp = based;
    b2fs_string_t data;
    memset(&data, 0, sizeof(b2fs_string_t));

    // Set URL for request.
    curl_easy_setopt(curl, CURLOPT_URL, url);

    // Create token to send for authentication.
    base64_encodestate state;
    base64_init_encodestate(&state);
    sprintf(conversionbuf, "%s:%s", config->account_id, config->app_key);
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
        token_count = jsmn_parse(&parser, data.str, strlen(data.str), tokens, B2FS_SMALL_GENERIC_BUFFER);
        if (token_count == JSMN_ERROR_NOMEM || tokens[0].type != JSMN_OBJECT) {
          free(data.str);
          return B2FS_NETWORK_API_ERROR;
        }

        // Iterate over returned tokens and extract the needed info.
        memset(b2_info, 0, sizeof(b2fs_state_t));
        for (int i = 1; i < token_count; i++) {
          jsmntok_t *key = &tokens[i++], *value = &tokens[i];
          int len = value->end - value->start;

          if (jsmn_iskey(data.str, key, "authorizationToken")) {
            memcpy(b2_info->token, data.str + value->start, len);
          } else if (jsmn_iskey(data.str, key, "apiUrl")) {
            memcpy(b2_info->api_url, data.str + value->start, len);
          } else if (jsmn_iskey(data.str, key, "downloadUrl")) {
            memcpy(b2_info->down_url, data.str + value->start, len);
          } else if (!jsmn_iskey(data.str, key, "accountId")) {
            LOG_KEY(data.str, key, "authentication");
          }
        }
        free(data.str);

        // Validate and return!
        if (strlen(b2_info->token) && strlen(b2_info->api_url) && strlen(b2_info->down_url)) {
          return B2FS_SUCCESS;
        } else {
          return B2FS_NETWORK_API_ERROR;
        }
      } else if (code == 401) {
        // Our authentication request was rejected due to bad auth info.
        free(data.str);
        return B2FS_NETWORK_ACCESS_ERROR;
      } else {
        // Request was badly formatted. Denotes an internal error.
        strncpy(b2_info->token, data.str, B2FS_TOKEN_LEN - 1);
        b2_info->token[B2FS_TOKEN_LEN - 1] = '\0';
        free(data.str);
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

int init_file_entry(b2fs_file_entry_t *entry) {
  if (!entry) return B2FS_INVAL;

  memset(entry, 0, sizeof(b2fs_file_entry_t));
  entry->chunkmap = create_bitmap();
  entry->chunks = create_keytree(free, free, intcmp, sizeof(int), sizeof(b2fs_file_chunk_t));
  entry->versions = create_keytree(free, free, rev_intcmp, sizeof(size_t), sizeof(b2fs_file_version_t));
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
  free(entry);
}

void destroy_hash_entry(void *voidarg) {
  b2fs_hash_entry_t *entry = voidarg;

  // Identify entry type and destroy.
  if (entry->type == TYPE_DIRECTORY) hash_destroy(entry->directory);
  else destroy_file_entry(&entry->file);
}

char **split_path(char *path) {
  char **parts = malloc(sizeof(char *) * B2FS_SMALL_GENERIC_BUFFER), *strtok_ptr;
  int size = B2FS_SMALL_GENERIC_BUFFER, counter = 0;

  // Iterate across string, reallocating as we go, and store token pointers.
  for (char *current = strtok_r(path, "/", &strtok_ptr); current; current = strtok_r(NULL, "/", &strtok_ptr)) {
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
  for (char *piece = path_pieces[i++]; path_pieces[i]; piece = path_pieces[i++]) {
    b2fs_hash_entry_t entry;
    int retval = hash_get(current, piece, &entry);

    if (retval != HASH_SUCCESS) {
      // Create a new hash entry of type directory.
      b2fs_hash_entry_t new_entry;
      new_entry.type = TYPE_DIRECTORY;
      new_entry.directory = create_hash(sizeof(b2fs_hash_entry_t), destroy_hash_entry);

      // Put it in the previous directory.
      hash_put(current, piece, &new_entry);
      hash_get(current, piece, &entry);
    } else if (entry.type != TYPE_DIRECTORY) {
      // An intermediate piece was not a directory. Give up and return.
      return NULL;
    }

    current = entry.directory;
  }

  // Move final piece up to front of array for ease of access.
  path_pieces[0] = path_pieces[i - 1];

  // Return the directory containing the file.
  return current;
}

int find_path(char *path, hash_t *base, b2fs_hash_entry_t *buf) {
  char **path_pieces = split_path(path);
  int i = 0;
  hash_t *current = base;

  b2fs_hash_entry_t entry;
  for (char *piece = path_pieces[i++]; path_pieces[i - 1]; piece = path_pieces[i++]) {
    // Get the entry and perform basic validation.
    int retval = hash_get(current, piece, &entry);
    if (retval != HASH_SUCCESS) return B2FS_FS_NOENT_ERROR;
    else if (entry.type == TYPE_FILE && path_pieces[i]) return B2FS_FS_NOTDIR_ERROR;

    if (entry.type == TYPE_DIRECTORY) current = entry.directory;
  }

  // Return whatever we found.
  memcpy(buf, &entry, sizeof(b2fs_hash_entry_t));
  return B2FS_SUCCESS;
}

int internal_make(const char *path, hash_t *base, b2fs_entry_type_t type) {
  // We are being asked to create a normal file. Ensure that the parent directory exists.
  char *end, *child_path;
  hash_t *parent;

  // Iterate across path and stop on last slash.
  for (char *curr = strstr(path, "/"); curr; end = curr, curr = strstr(curr + 1, "/"));
  int path_len = end - path, filename_len = strlen(++end);
  child_path = malloc(sizeof(char) * (filename_len + 1));
  strcpy(child_path, end);

  if (path_len) {
    // We're creating a file somewhere other than the root.
    char *parent_path = malloc(sizeof(char) * path_len);
    memcpy(parent_path, path, path_len);
    parent_path[path_len] = '\0';

    // Attempt to locate the parent directory and return an error if it can't be found.
    b2fs_hash_entry_t entry;
    int retval = find_path(parent_path, base, &entry);
    free(parent_path);
    if (retval == B2FS_FS_NOTDIR_ERROR || entry.type != TYPE_DIRECTORY) {
      free(child_path);
      return -ENOTDIR;
    } else if (retval == B2FS_FS_NOENT_ERROR) {
      free(child_path);
      return -ENOENT;
    }
    parent = entry.directory;
  } else {
    // We're inserting into the root directory.
    parent = base;
  }

  // Initialize new directory entry for insertion.
  b2fs_hash_entry_t created;
  created.type = type;
  if (type == TYPE_FILE) init_file_entry(&created.file);
  else created.directory = create_hash(sizeof(b2fs_hash_entry_t), destroy_hash_entry);

  // Insert the requested entry into the filesystem cache. B2 doesn't support empty files
  // or directories, so we just need to keep track of the fact that it exists until the
  // user decides to write some data.
  int retval = hash_put(parent, child_path, &created);
  if (retval == HASH_SUCCESS) return B2FS_SUCCESS;
  else return -EEXIST;
}

int jsmn_iskey(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type != JSMN_STRING) return 0;
  if (((int) strlen(s)) != (tok->end - tok->start)) return 0;
  if (strncmp(json + tok->start, s, tok->end - tok->start)) return 0;
  return 1;
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

int parse_config(b2fs_config_t *config, char *config_filename) {
  FILE *config_file = fopen(config_filename, "r");
  char keybuf[B2FS_SMALL_GENERIC_BUFFER], valbuf[B2FS_SMALL_GENERIC_BUFFER];

  if (config_file) {
    for (int i = 0; i < 5; i++) {
      int retval = fscanf(config_file, "%s %s\n", keybuf, valbuf);
      if (retval != 2) break;

      if (!strcmp(keybuf, "account_id:") && !strlen(config->account_id)) {
        strcpy(config->account_id, valbuf);
      } else if (!strcmp(keybuf, "bucket:") && !strlen(config->bucket_id)) {
        strcpy(config->bucket_id, valbuf);
      } else if (!strcmp(keybuf, "app_key:") && !strlen(config->app_key)) {
        strcpy(config->app_key, valbuf);
      } else if (!strcmp(keybuf, "mount:")) {
        strcpy(config->mount_point, valbuf);
      } else if (!strcmp(keybuf, "delete_policy:") && config->policy == POLICY_INVAL) {
        if (!strcmp(valbuf, "hide")) config->policy = POLICY_HIDE;
        else if (!strcmp(valbuf, "delete")) config->policy = POLICY_DELETE_ONE;
        else if (!strcmp(valbuf, "delete_all")) config->policy = POLICY_DELETE_ALL;
        else return B2FS_GENERIC_ERROR;
      } else {
        return B2FS_GENERIC_ERROR;
      }
    }
    return B2FS_SUCCESS;
  } else {
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

int rev_intcmp(void *int_one, void *int_two) {
  return *((int *) int_two) - *((int *) int_one);
}

void print_usage(int intentional) {
  puts("./b2fs <--config | YAML file to read config from> <--mount | Mount point>");
  exit(intentional ? EXIT_SUCCESS : EXIT_FAILURE);
}
