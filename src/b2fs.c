/*----- Constants -----*/

// Error codes.
#define B2FS_SUCCESS 0x00
#define B2FS_ERROR -0x01
#define B2FS_INVAL_ERROR -0x02
#define B2FS_NOMEM_ERROR -0x04
#define B2FS_NETWORK_ERROR -0x08
#define B2FS_NETWORK_ACCESS_ERROR -0x0100
#define B2FS_NETWORK_INTERN_ERROR -0x0101
#define B2FS_NETWORK_API_ERROR -0x0102
#define B2FS_NETWORK_TOKEN_ERROR -0x0104
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
#include <pthread.h>

/*----- Local Includes -----*/

#include "b64/cencode.h"
#include "jsmn/jsmn.h"
#include "structures/hash.h"
#include "structures/array.h"
#include "structures/bitmap.h"
#include "structures/stack.h"
#include "structures/queue.h"
#include "structures/keytree.h"

/*----- Macro Declarations -----*/

// Fun little hack for calculating the sizes of struct fields.
// Second macro follows through to the type being pointed at.
#define MEMBER_SIZE(type, member) sizeof(((type *) 0)->member)
#define MEMBER_PTR_SIZE(type, member) sizeof(*((type *) 0)->member)

#ifdef DEBUG

#define write_log(level, ...)                                                                             \
  do {                                                                                                    \
    printf(__VA_ARGS__);                                                                                  \
  } while (0);

#elif INFO

#define write_log(level, ...)                                                                             \
  do {                                                                                                    \
    if (level == LEVEL_INFO) printf(__VA_ARGS__)                                                          \
    else if (level == LEVEL_ERROR) fprintf(stderr, __VA_ARGS__);                                          \
  } while (0);

#else

#define write_log(level, ...)                                                                             \
  do {                                                                                                    \
    if (level == LEVEL_ERROR) fprintf(stderr, __VA_ARGS__);                                               \
  } while (0);

#endif

#define LOG_KEY(data, key, context)                                                                       \
  do {                                                                                                    \
    write_log(LEVEL_DEBUG, "B2FS: Encountered unexpected key in %s: %.*s\n",                              \
        context, key->end - key->start, data + key->start);                                               \
  } while (0);

// This macro makes me very sad, and goes against my better judgement, but cURL setup has just
// become boilerplate at this point.
// If cURL fails to initialize, this code will probably crash, but to be honest I'm not
// entirely sure what the "correct" decision would be under that situation as it likely would
// be indicative of a fatal error.
#define INITIALIZE_LIBCURL(curl, base, uri, token, lock, header, write_var, write_func, post)             \
  char urlbuf[B2FS_SMALL_GENERIC_BUFFER], auth[B2FS_SMALL_GENERIC_BUFFER], tok[B2FS_TOKEN_LEN];           \
  strcpy(tok, token);                                                                                     \
  sprintf(urlbuf, "%s/%s", base, uri);                                                                    \
  curl_easy_setopt(curl, CURLOPT_URL, urlbuf);                                                            \
  if (post) curl_easy_setopt(curl, CURLOPT_POST, 1L);                                                     \
  sprintf(auth, header, token);                                                                           \
  struct curl_slist *headers = NULL;                                                                      \
  headers = curl_slist_append(headers, auth);                                                             \
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);                                                    \
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_func);                                              \
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_var);

// Be careful using this macro as it will cause the larger argument to be evaluated twice.
#define MAX(a, b) ((a) > (b) ? (a) : (b))

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
  size_t size;
  int *should_delete, *hidden, *live, *synced;
} b2fs_file_version_t;

typedef struct b2fs_file_chunk {
  int chunk_num, size;
  char data[B2FS_CHUNK_SIZE];
} b2fs_file_chunk_t;

// FIXME: File versions currently uses a keytree where a stack or queue would most
// likely be more appropriate because I'm not sure I trust B2 to return file versions
// in proper reverse-upload order. Or, rather, I don't want my code to crash if they
// change this, and keytree will enforce its own internal ordering.
typedef struct b2fs_file_entry {
  bitmap_t *chunkmap;
  keytree_t *chunks, *versions;
  int readers, writers;
} b2fs_file_entry_t;

typedef struct b2fs_dir_entry {
  hash_t *directory;
  int *hidden;
} b2fs_dir_entry_t;

typedef struct b2fs_hash_entry {
  b2fs_entry_type_t type;
  union {
    b2fs_file_entry_t file;
    b2fs_dir_entry_t dir;
  };
} b2fs_hash_entry_t;

typedef struct b2fs_version_sync_state {
  size_t timestamp;
  int pos;
} b2fs_version_sync_state_t;

typedef struct b2fs_state {
  char token[B2FS_TOKEN_LEN], api_url[B2FS_TOKEN_LEN];
  char down_url[B2FS_TOKEN_LEN];
  b2fs_config_t config;
  hash_t *fs_cache, *id_mappings;
  pthread_rwlock_t lock;
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
int b2_list_versions(hash_t *fs_cache, const char *target_path, keytree_t *synced);
size_t receive_string(void *data, size_t size, size_t nmembers, void *voidarg);
int b2_sync_versions(b2fs_file_entry_t *entry, const char *path);
int handle_b2_error(b2fs_state_t *state, char *response, char *cached_token);
int handle_authentication(b2fs_state_t *state, char *account_id, char *app_key);

// Struct Initializers.
int init_file_entry(b2fs_file_entry_t *entry);
int init_file_version(b2fs_file_version_t *version);
int init_dir_entry(b2fs_dir_entry_t *entry);
void destroy_file_entry(void *voidarg);
void destroy_file_version(void *voidarg);
void destroy_hash_entry(void *voidarg);

// Filesystem Helpers.
char **split_path(char *path);
hash_t *make_path(char **path_pieces, hash_t *base, b2fs_dir_entry_t *output);
int find_path(char *path, hash_t *base, b2fs_hash_entry_t *buf, int honor_hidden);
int internal_make(const char *path, hash_t *base, b2fs_entry_type_t type);

// Generic Helper Functions.
int jsmn_iskey(const char *json, jsmntok_t *tok, const char *s);
void cache_auth(b2fs_state_t *b2_info);
int find_cached_auth(b2fs_state_t *b2_info);
int parse_config(b2fs_config_t *config, char *config_filename);
void find_tmpdir(char **out);
int intcmp(void *int_one, void *int_two);
int rev_intcmp(void *int_one, void *int_two);
void dereference_and_destroy(void *destroyed);
void print_usage(int intentional);

/*----- Local Function Implementations -----*/

int main(int argc, char **argv) {
  int c, index, retval;
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
    retval = handle_authentication(&b2_info, config.account_id, config.app_key);

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
      case B2FS_NETWORK_ERROR:
        write_log(LEVEL_DEBUG, "B2FS: cURL error encountered. Reason: %s\n", b2_info.token);
        write_log(LEVEL_ERROR, "B2FS: Network library error. Please try again.\n");
        break;
      case B2FS_ERROR:
        write_log(LEVEL_ERROR, "B2FS: Failed to initialize network.\n");
    }
    if (retval != B2FS_SUCCESS) return EXIT_FAILURE;

    // Cache new auth info.
    cache_auth(&b2_info);
  }

  // We are authenticated and have a valid token. Finish state initialization.
  b2_info.config = config;
  pthread_rwlock_init(&b2_info.lock, NULL);

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

// TODO: This function is crazy long and out of control. Refactoring won't help a whole lot,
// because most of what it does is necessary, but I could break it out into constituent functions.
void *b2fs_init(struct fuse_conn_info *info) {
  (void) info;
  b2fs_state_t *state = fuse_get_context()->private_data;

  // Initialize global data structures.
  state->fs_cache = create_hash(sizeof(b2fs_hash_entry_t), destroy_hash_entry);
  state->id_mappings = create_hash(sizeof(char *), dereference_and_destroy);
  if (!state->fs_cache || !state->id_mappings) {
    write_log(LEVEL_ERROR, "B2FS: Could not allocate enough memory to start up.\n");
    if (state->fs_cache) hash_destroy(state->fs_cache);
    if (state->id_mappings) hash_destroy(state->id_mappings);
    fuse_exit(fuse_get_context()->fuse);
  }

  // Initialize filesystem cache.
  int retval = b2_list_versions(state->fs_cache, NULL, NULL);
  if (retval != B2FS_SUCCESS) {
    switch (retval) {
      case B2FS_NOMEM_ERROR:
        write_log(LEVEL_DEBUG, "B2FS: Failed to allocate enough tokens for initial fs caching...\n");
        write_log(LEVEL_ERROR, "B2FS: Could not allocate enough memory to start up.\n");
        break;
      case B2FS_NETWORK_API_ERROR:
        write_log(LEVEL_ERROR, "B2FS: B2 returned an invalid response during startup.\n");
        break;
      case B2FS_NETWORK_ERROR:
        write_log(LEVEL_ERROR, "B2FS: Failed to initialize network during starup.\n");
        break;
      default:
        write_log(LEVEL_DEBUG, "B2FS: b2_list_file_versions returned an unexpected value...\n");
        write_log(LEVEL_ERROR, "B2FS: Encountered an unexpected fatal error during startup.\n");
    }

    // We're still in startup, a failure this early doesn't bode well. Just error out.
    hash_destroy(state->fs_cache);
    hash_destroy(state->id_mappings);
    fuse_exit(fuse_get_context()->fuse);
  }

  // Filesystem is cached. Now need to create id->name mappings for files.
  // Create hash_entry for fs_cache to be able to use the general case.
  b2fs_hash_entry_t current_entry, start_entry;
  start_entry.type = TYPE_DIRECTORY;
  start_entry.dir.directory = state->fs_cache;

  // Create storage for the current total path and path section.
  b2fs_string_t current_path;
  char current_section[B2FS_MED_GENERIC_BUFFER];
  memset(&current_path, 0, sizeof(b2fs_string_t));
  memset(current_section, 0, sizeof(char) * B2FS_MED_GENERIC_BUFFER);
  current_path.str = malloc(sizeof(char) * B2FS_SMALL_GENERIC_BUFFER);
  current_path.len = B2FS_SMALL_GENERIC_BUFFER;

  // Create queues.
  queue_t *dirs = create_queue(NULL, sizeof(b2fs_hash_entry_t)), *sections = create_queue(NULL, sizeof(char) * B2FS_MED_GENERIC_BUFFER);
  queue_enqueue(dirs, &start_entry);
  queue_enqueue(sections, &current_section);
  while (queue_dequeue(dirs, &current_entry) == QUEUE_SUCCESS) {
    // Get the name of the current path section.
    assert(queue_dequeue(sections, &current_section) == QUEUE_SUCCESS);

    if (!strcmp(current_section, "..")) {
      // We've reached the end of a directory.
      while (*(current_path.str + --current_path.ptr) != '/');

      // FIXME: Remove this after development.
      assert(current_path.ptr >= 0);

      *(current_path.str + current_path.ptr) = '\0';
      continue;
    }

    // Append the current section onto the end of the path.
    int len = strlen(current_section);
    if (current_path.ptr + len > current_path.len) {
      // String is too small, add more room.
      current_path.len = MAX(current_path.len * 2, current_path.ptr + len + 1);
      void *tmp = realloc(current_path.str, sizeof(char) * current_path.len);
      if (!tmp) {
        // Memory couldn't be allocated for the string. We're still in startup, so
        // just fail out.
        write_log(LEVEL_DEBUG, "B2FS: String allocation failed during startup...\n");
        write_log(LEVEL_ERROR, "B2FS: Could not allocate enough memory to start up.\n");
        free(current_path.str);
        destroy_queue(dirs);
        destroy_queue(sections);
        hash_destroy(state->fs_cache);
        hash_destroy(state->id_mappings);
        fuse_exit(fuse_get_context()->fuse);
      }
      current_path.str = tmp;
    }
    *(current_path.str + current_path.ptr++) = '/';
    strcpy(current_path.str + current_path.ptr, current_section);
    current_path.ptr += len;
    *(current_path.str + current_path.ptr) = '\0';

    if (current_entry.type == TYPE_FILE) {
      // Finally, what we're actually doing all of this for.
      keytree_iterator_t *it = keytree_iterate_start(current_entry.file.versions, NULL);
      b2fs_file_version_t version;

      // Iterate across versions and cache each id->path.
      while (keytree_iterate_next(it, NULL, &version) == KEYTREE_SUCCESS) {
        char *path_copy = malloc(sizeof(char) * current_path.ptr);
        strcpy(path_copy, current_path.str);
        hash_put(state->id_mappings, version.version_id, &path_copy);
      }

      keytree_iterate_stop(it);
    } else {
      // Current entry is a directory, add all of its contents to the queue.
      char **contents = hash_keys(current_entry.dir.directory, NULL);
      for (int i = 0; i < hash_count(current_entry.dir.directory); i++) {
        b2fs_hash_entry_t tmp_entry;
        char *entry = contents[i];
        strcpy(current_section, entry);

        assert(hash_get(current_entry.dir.directory, current_section, &tmp_entry) == HASH_SUCCESS);
        queue_enqueue(dirs, &tmp_entry);
        queue_enqueue(sections, &current_section);
      }

      // Enqueue a stop record to signify that the directory is finished.
      strcpy(current_section, "..");
      queue_enqueue(dirs, &current_entry);
      queue_enqueue(sections, &current_section);

      free(contents);
    }
  }
  destroy_queue(dirs);
  destroy_queue(sections);
  free(current_path.str);

  // Boy, that was long and complicated, but now we're done.
  return state;
}

// TODO: Implement this function.
void b2fs_destroy(void *userdata) {
  (void) userdata;
}

// Function returns basic information for a given file path.
int b2fs_getattr(const char *path, struct stat *statbuf) {
  b2fs_state_t *state = fuse_get_context()->private_data;

  int retval;
  b2fs_hash_entry_t entry;
  b2fs_file_version_t version;
  if (strcmp(path, "/")) {
    char *path_copy = malloc(sizeof(char) * (strlen(path) + 1));
    strcpy(path_copy, path);
    retval = find_path(path_copy, state->fs_cache, &entry, 1);
    free(path_copy);
  } else {
    entry.type = TYPE_DIRECTORY;
    retval = B2FS_SUCCESS;
  }

  // Check if entry was found.
  if (retval == B2FS_SUCCESS) {
    // Check to make sure the file hasn't been hidden.
    // No need to check for directories as find_path will return failure if
    // directory is hidden.
    size_t timestamp;
    if (entry.type == TYPE_FILE) {
      b2fs_file_version_t version;

      // Get most recent version of file.
      keytree_iterator_t *it = keytree_iterate_start(entry.file.versions, NULL);
      assert(keytree_iterate_next(it, &timestamp, &version) == KEYTREE_SUCCESS);
      keytree_iterate_stop(it);

      // Only provide attributes for the file if it's not hidden.
      if (*version.hidden) return -ENOENT;
    }

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
    int retval = find_path(path_copy, state->fs_cache, &entry, 1);
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
    int retval = find_path(path_copy, state->fs_cache, &entry, 1);
    free(path_copy);

    // Should be impossible for find_path to return an error if this code is correct.
    assert(retval == B2FS_SUCCESS);

    // I'm assuming that all necessary validation for the path is done by b2fs_opendir, and that we
    // already know that the given path exists and is a directory.
    directory = entry.dir.directory;
  } else {
    // User is asking to open /. Just use fs_cache.
    directory = state->fs_cache;
  }

  // Iterate across the keys and pass them to the filler function.
  int num_entries;
  char **keys = hash_keys(directory, &num_entries);
  for (int i = 0; i < num_entries; i++) {
    // Before returning the current file, we need to make sure it hasn't been hidden.
    b2fs_hash_entry_t entry;
    b2fs_file_version_t version;
    assert(hash_get(directory, keys[i], &entry) == HASH_SUCCESS);

    if (entry.type == TYPE_FILE) {
      // Get the most recent version.
      keytree_iterator_t *it = keytree_iterate_start(entry.file.versions, NULL);
      assert(keytree_iterate_next(it, NULL, &version) == KEYTREE_SUCCESS);

      // Return the entry if it's not hidden.
      if (!*version.hidden) filler(buf, keys[i], NULL, 0);
    } else {
      filler(buf, keys[i], NULL, 0);
    }

  }
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

// Function takes care of deleting a file. Performs (perhaps unnecessary) validation to make sure
// the path isn't a directory, then removes the file from the local cache based on the deletion
// policy. File is removed from B2 in the file version destructor.
// FIXME: Function needs to be re-written to be threadsafe, and we also need to add some notion
// of whether or not a particular file version is actually present in B2.
int b2fs_unlink(const char *path) {
  b2fs_state_t *state = fuse_get_context()->private_data;

  // Locate the file to make sure it exists.
  if (strcmp(path, "/")) {
    // Find requested directory.
    b2fs_hash_entry_t entry;
    char *path_copy = malloc(sizeof(char) * (strlen(path) + 1));
    strcpy(path_copy, path);
    int retval = find_path(path_copy, state->fs_cache, &entry, 1);
    free(path_copy);

    if (retval == B2FS_SUCCESS) {
      // File exists. Time to do the hard work.
      int synced = 0;

      if (state->config.policy != POLICY_HIDE) {
        // Figure out how many files we need to delete.
        int num_iterations = state->config.policy == POLICY_DELETE_ONE ? 1 : keytree_size(entry.file.versions);

        // Make sure that our file versions have their corresponding ids.
        b2_sync_versions(&entry.file, path);
        synced = 1;

        // Iterate over versions and mark for deletion.
        size_t key;
        b2fs_file_version_t version;
        stack_t *deletions = create_stack(NULL, sizeof(size_t));
        keytree_iterator_t *it = keytree_iterate_start(entry.file.versions, NULL);
        while (num_iterations-- && keytree_iterate_next(it, &key, &version) == KEYTREE_SUCCESS) {
          *version.should_delete = 1;
          stack_push(deletions, &key);
        }
        keytree_iterate_stop(it);

        // Remove versions from the version tree (will call destructor to delete from B2).
        while (stack_pop(deletions, &key) == STACK_SUCCESS) keytree_remove(entry.file.versions, &key, NULL);
        destroy_stack(deletions);
      }

      // Hide the earliest remaining file if there is one.
      if (keytree_size(entry.file.versions) > 0) {
        // Perform version sync if we didn't already do it.
        // Operation is idempotent, so check is superfluous, but no reason to do
        // extra work.
        if (!synced) b2_sync_versions(&entry.file, path);

        // Do-while loop works as a conditional retry-loop if our auth token is expired.
        int do_again;
        do {
          CURL *curl = curl_easy_init();
          CURLcode res;
          char body[B2FS_SMALL_GENERIC_BUFFER], *filename;
          b2fs_string_t response;
          do_again = 0;
          memset(&response, 0, sizeof(b2fs_string_t));

          // Big, dirty, macro to handle all of the boilerplate cURL initialization stuff.
          // Acquire read-lock to make sure we're using the right auth token and stuff.
          pthread_rwlock_rdlock(&state->lock);
          INITIALIZE_LIBCURL(
              curl,
              state->api_url,
              "b2api/v1/b2_hide_file",
              state->token,
              state->lock,
              "Authorization: %s",
              response,
              receive_string,
              1);
          pthread_rwlock_unlock(&state->lock);

          // Get the most recent remaining version.
          b2fs_file_version_t version;
          keytree_iterator_t *it = keytree_iterate_start(entry.file.versions, NULL);
          assert(keytree_iterate_next(it, NULL, &version) == KEYTREE_SUCCESS);
          keytree_iterate_stop(it);

          // Get the name of the file exactly as B2 expects it and create the request body.
          assert(hash_get(state->id_mappings, version.version_id, &filename) == HASH_SUCCESS);
          sprintf(body, "{\"bucketId\":\"%s\",\"fileName\":\"%s\"}", state->config.bucket_id, filename);
          curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);

          // Perform the request.
          if ((res = curl_easy_perform(curl)) == CURLE_OK) {
            long code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

            if (code == 200) {
              // No need to check response. Hide API just returns info on the file that we already have, and the API docs state that
              // a 200 is sufficient to know that the file has been hidden.
              *version.hidden = 1;
              free(response.str);
            } else {
              write_log(LEVEL_DEBUG, "B2FS: B2 returned error code %ld with message: %s\n", code, response.str);

              // Attempt to handle the returned error.
              int retval = handle_b2_error(state, response.str, tok);

              // Regardless of what happens, this stuff needs to be cleaned up.
              free(response.str);
              memset(&response, 0, sizeof(b2fs_string_t));

              // Check the reason the error was generated, and if it was handled.
              // TODO: Currently only one supported reason, so I may need to add more clauses here eventually.
              if (retval == B2FS_NETWORK_TOKEN_ERROR) {
                // Do the request again.
                do_again = 1;
              } else {
                // The error wasn't handled, and we don't know what went wrong. Return a generic IO error.
                curl_slist_free_all(headers);
                curl_easy_cleanup(curl);
                return -EIO;
              }
            }
          } else {
            // FIXME: At the moment, this currently just reports a generic IO error if cURL fails to perform the request.
            // Perhaps add more detailed error handling here eventually.
            write_log(LEVEL_DEBUG, "B2FS: cURL returned error code %s while hiding the file %s.\n", curl_easy_strerror(res), filename);
            return -EIO;
          }

          // Clean up cURL resources.
          curl_slist_free_all(headers);
          curl_easy_cleanup(curl);
        } while (do_again);
      }

      // Remove the file from the filesystem cache if all versions have been removed.
      if (!keytree_size(entry.file.versions)) {
        path_copy = malloc(sizeof(char) * strlen(path) + 1);
        strcpy(path_copy, path);
        char **path_pieces = split_path(path_copy);
        hash_t *parent = make_path(path_pieces, state->fs_cache, NULL);
        assert(hash_drop(parent, path_pieces[0]) == HASH_SUCCESS);
        free(path_copy);
        destroy_hash_entry(&entry);
      }

      return B2FS_SUCCESS;
    } else if (retval == B2FS_FS_NOENT_ERROR) {
      // File doesn't exist.
      return -ENOENT;
    } else {
      // An intermediate path entry isn't a directory.
      return -ENOTDIR;
    }
  } else {
    // User is asking for us to unlink the root directory.
    // This call is only supposed to be used for files. Don't know if this
    // would ever actually happen.
    return -EISDIR;
  }
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
    int retval = find_path(path_copy, state->fs_cache, &entry, 1);
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

// 
int b2_list_versions(hash_t *fs_cache, const char *target_path, keytree_t *synced) {
  b2fs_state_t *state = fuse_get_context()->private_data;

  // Do-While loop works as a conditional retry-loop if our auth token is expired.
  int do_again;
  do {
    CURL *curl = curl_easy_init();
    CURLcode res;
    char start_fileid[B2FS_SMALL_GENERIC_BUFFER], start_filename[B2FS_SMALL_GENERIC_BUFFER];
    char body[B2FS_SMALL_GENERIC_BUFFER];
    b2fs_string_t response;
    do_again = 0;
    memset(&response, 0, sizeof(b2fs_string_t));
    memset(start_fileid, 0, sizeof(char) * B2FS_SMALL_GENERIC_BUFFER);
    memset(start_filename, 0, sizeof(char) * B2FS_SMALL_GENERIC_BUFFER);

    // Big, dirty, macro to handle all of the boilerplate cURL initialization stuff.
    // Acquire read-lock to ensure we're using the most recent auth tokens and everything.
    pthread_rwlock_rdlock(&state->lock);
    INITIALIZE_LIBCURL(
        curl,
        state->api_url,
        "b2api/v1/b2_list_file_versions",
        state->token,
        state->lock,
        "Authorization: %s",
        response,
        receive_string,
        1);
    pthread_rwlock_unlock(&state->lock);

    // Loop until all files have been loaded.
    // Declare found_file flag to jump out early when searching for a particular
    // file.
    int found_file = 0;
    while (!found_file && strcmp(start_filename, "null") && strcmp(start_fileid, "null")) {
      // Set POST body.
      if (strlen(start_filename) || strlen(start_fileid)) {
        // Quick sanity checking.
        assert(strlen(start_filename) && strlen(start_fileid));

        // I hate putting single calls on multiple lines, but this is otherwise too long.
        sprintf(body,
            "{\"bucketId\":\"%s\",\"startFileName\":\"%s\",\"startFileId\":\"%s\",\"maxFileCount\":1000}",
            state->config.bucket_id, start_filename, start_fileid);
      } else {
        sprintf(body, "{\"bucketId\":\"%s\",\"maxFileCount\":1000}", state->config.bucket_id);
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
            jsmn_init(&parser);
            token_count = jsmn_parse(&parser, response.str, strlen(response.str), tokens, B2FS_MED_GENERIC_BUFFER * i);
            if (token_count == JSMN_ERROR_NOMEM) {
              void *tmp = realloc(tokens, sizeof(jsmntok_t) * (B2FS_MED_GENERIC_BUFFER * (i + 1)));
              if (!tmp) {
                if (tokens) free(tokens);
                curl_slist_free_all(headers);
                curl_easy_cleanup(curl);
                return B2FS_NOMEM_ERROR;
              }
              tokens = tmp;
            } else if (token_count == JSMN_ERROR_INVAL || token_count == JSMN_ERROR_PART) {
              write_log(LEVEL_DEBUG, "B2FS: B2 returned invalid JSON during list_file_versions: %s...\n", response.str);
              if (tokens) free(tokens);
              curl_slist_free_all(headers);
              curl_easy_cleanup(curl);
              return B2FS_NETWORK_API_ERROR;
            }
          }

          // Zero start_filename and start_fileid to ensure null termination.
          memset(start_filename, 0, sizeof(char) * B2FS_SMALL_GENERIC_BUFFER);
          memset(start_fileid, 0, sizeof(char) * B2FS_SMALL_GENERIC_BUFFER);
          for (int i = 1; !found_file && i < token_count; i++) {
            jsmntok_t *key = &tokens[i++], *value = &tokens[i++];
            int len = value->end - value->start, token_index = i;

            if (jsmn_iskey(response.str, key, "files")) {
              for (int j = 0; j < value->size; j++) {
                jsmntok_t *file = &tokens[token_index++];
                b2fs_hash_entry_t entry;
                b2fs_file_version_t version;
                char **path_pieces, filename[B2FS_MED_GENERIC_BUFFER], *id_mapping;
                long size, timestamp;

                // Initialize this file version.
                init_file_version(&version);

                // Parse out file path pieces and file size.
                for (int k = 0; k < file->size; k++) {
                  jsmntok_t *obj_key = &tokens[token_index++], *obj_value = &tokens[token_index++];
                  int obj_len = obj_value->end - obj_value->start;

                  if (jsmn_iskey(response.str, obj_key, "fileName")) {
                    // Copy filename into local buffer to split into pieces.
                    memset(filename, 0, sizeof(char) * B2FS_MED_GENERIC_BUFFER);
                    memcpy(filename, response.str + obj_value->start, obj_len);

                    // If the caller specified an exact file that we're looking for,
                    // skip any that aren't the target.
                    if (target_path && strcmp(target_path, filename) && found_file) break;
                    else if (target_path && strcmp(target_path, filename)) continue;

                    // Split path.
                    path_pieces = split_path(filename);
                  } else if (jsmn_iskey(response.str, obj_key, "size")) {
                    version.size = strtol(response.str + obj_value->start, NULL, 10);
                  } else if (jsmn_iskey(response.str, obj_key, "uploadTimestamp")) {
                    timestamp = strtol(response.str + obj_value->start, NULL, 10);
                  } else if (jsmn_iskey(response.str, obj_key, "fileId")) {
                    memset(version.version_id, 0, sizeof(char) * B2FS_SMALL_GENERIC_BUFFER);
                    memcpy(version.version_id, response.str + obj_value->start, obj_len);
                  } else if (jsmn_iskey(response.str, obj_key, "action")) {
                    // Set the  hidden flag if the action is set to hide.
                    if (!strncmp(response.str + obj_value->start, "hide", obj_len)) {
                      *version.hidden = 1;
                    }
                  }
                }

                // Continue to propagate breaking if we've found our target file.
                if (target_path && strcmp(target_path, filename) && found_file) {
                  free(path_pieces);
                  break;
                }

                // Validate and add liveness flags.
                assert(strlen(version.version_id) > 0);
                *version.live = 1;
                *version.synced = 1;
                if (fs_cache) {
                  // Make all intermediate directories and grab parent.
                  b2fs_dir_entry_t directory;
                  hash_t *dir = make_path(path_pieces, fs_cache, &directory);

                  if (hash_get(dir, path_pieces[0], &entry) != HASH_SUCCESS) {
                    // Hash entry does not exist. This is the first time we've seen this file.
                    entry.type = TYPE_FILE;
                    init_file_entry(&entry.file);
                    hash_put(dir, path_pieces[0], &entry);
                  }
                  keytree_insert(entry.file.versions, &timestamp, &version);

                  // Highly inelegant way of persisting directory deletions across restarts when B2FS is
                  // configured to only hide deleted files. B2 doesn't support hiding directories, so there's
                  // no way to disambiguate between a directory that exists, but has had all of its contents
                  // hidden, and a directory that has been explicitly deleted. Thus, in the latter case, we
                  // insert a .b2fs_hidefile entry to assert that the directory should, in fact, be hidden.
                  // Pretty not great, but it works.
                  if (!strcmp(path_pieces[0], ".b2fs_hidefile")) *directory.hidden = 1;
                } else if (target_path && synced) {
                  found_file = 1;
                  keytree_insert(synced, &timestamp, &version);
                } else {
                  write_log(LEVEL_DEBUG, "B2FS: Got into invalid branch for b2_list_versions...\n");
                  return B2FS_ERROR;
                }

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
          memset(&response, 0, sizeof(b2fs_string_t));
        } else {
          // B2 returned an error.
          write_log(LEVEL_DEBUG, "B2FS: B2 returned error code %ld with message: %s\n", code, response.str);

          // Attempt to handle the returned error.
          int retval = handle_b2_error(state, response.str, tok);

          // Check the reason the error was generated.
          // TODO: Currently only one supported reason, so I may need to add more clauses here eventually.
          if (retval == B2FS_NETWORK_TOKEN_ERROR) {
            do_again = 1;
            free(response.str);
            memset(&response, 0, sizeof(b2fs_string_t));
            break;
          } else {
            // Error couldn't be handled. We're in the process of starting up, so just shutdown.
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            free(response.str);
            return B2FS_NETWORK_API_ERROR;
          }
        }
      } else {
        write_log(LEVEL_DEBUG, "B2FS: cURL failed with error %s during list_file_versions.\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return B2FS_NETWORK_ERROR;
      }
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
  } while (do_again);

  return B2FS_SUCCESS;
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

// Given a file entry, iterates across the file versions and checks for an incomplete
// entry. If it finds any, replaced them all with B2 version.
int b2_sync_versions(b2fs_file_entry_t *entry, const char *path) {
  int should_sync = 0, live = 0, counter = 0;
  b2fs_state_t *state = fuse_get_context()->private_data;

  // Iterate across cached file versions.
  size_t timestamp;
  b2fs_file_version_t version;
  queue_t *syncables = create_queue(NULL, sizeof(b2fs_version_sync_state_t));
  keytree_iterator_t *it = keytree_iterate_start(entry->versions, NULL);
  while (keytree_iterate_next(it, &timestamp, &version) == KEYTREE_SUCCESS) {
    b2fs_version_sync_state_t state;

    if (*version.live) {
      live = 1;
      if (!*version.synced) {
        should_sync = 1;
        state.pos = counter;
        state.timestamp = timestamp;
        queue_enqueue(syncables, &state);
      }
      counter++;
    }

    // Soft assumption I'm making. Let's just make sure this holds.
    if (live) assert(*version.live);
  }

  // Sync any entries needing it.
  if (should_sync) {
    // First get file history from B2.
    keytree_t *versions = create_keytree(NULL, destroy_file_version, rev_intcmp, sizeof(size_t), sizeof(b2fs_file_version_t));

    // Really becoming frustrated with the B2 API, it's just so goddamn incomplete.
    // There's no way to list the file versions for a particular file path, so we
    // have to iterate across ALL FILES. The good news is that file versions at least
    // show up contiguously for each file path, so we can jump out early.
    // TODO: Revisit this sometime if B2 ever gets their shit together.
    int retval = b2_list_versions(NULL, path, versions);

    // Check if our sync was a success, and if so, destroy and overwrite the old history.
    if (retval == B2FS_SUCCESS) {
      keytree_destroy(entry->versions);
      entry->versions = versions;
    } else {
      keytree_destroy(versions);
    }

    return retval;
  } else {
    return B2FS_SUCCESS;
  }
}

// As the name suggests, this function is responsible for attempting to fix an error returned
// from B2. Currently only supports re-authentication.
// Contrary to the semantics of the other functions, this function actually returns the type of
// error that occured on success, and a generic network error on failure.
int handle_b2_error(b2fs_state_t *state, char *response, char *cached_token) {
  // Need to figure out what went wrong. Time to parse JSON.
  int token_count = JSMN_ERROR_NOMEM;
  jsmn_parser parser;
  jsmntok_t *tokens = malloc(sizeof(jsmntok_t) * B2FS_SMALL_GENERIC_BUFFER);

  // Make sure enough memory is available and parse response.
  for (int i = 1; token_count == JSMN_ERROR_NOMEM; i++) {
    jsmn_init(&parser);
    token_count = jsmn_parse(&parser, response, strlen(response), tokens, B2FS_SMALL_GENERIC_BUFFER * i);
    if (token_count == JSMN_ERROR_NOMEM) {
      void *tmp = realloc(tokens, sizeof(jsmntok_t) * (B2FS_SMALL_GENERIC_BUFFER * (i + 1)));
      if (!tmp) {
        write_log(LEVEL_DEBUG, "B2FS: Failed to allocate enough memory to parse B2 error message...\n");
        free(tokens);
        return B2FS_NOMEM_ERROR;
      }
      tokens = tmp;
    } else if (token_count == JSMN_ERROR_INVAL || token_count == JSMN_ERROR_PART) {
      write_log(LEVEL_DEBUG, "B2FS: B2 returned an invalid error message.\n");
      free(tokens);
      return B2FS_INVAL_ERROR;
    }
  }

  for (int i = 1; i < token_count; i++) {
    jsmntok_t *key = &tokens[i++], *value = &tokens[i];
    int len = value->end - value->start;

    if (jsmn_iskey(response, key, "code")) {
      char reason[B2FS_SMALL_GENERIC_BUFFER];
      memset(reason, 0, sizeof(char) * B2FS_SMALL_GENERIC_BUFFER);
      memcpy(reason, response + value->start, len);
      free(tokens);

      // TODO: The ultimate point to this function is to be able to handle many different potential error conditions from
      // B2, so I'll need to add more clauses here.
      if (!strcmp(reason, "expired_auth_token")) {
        // We received an error from B2 because our authentication token has expired. Acquire the write-lock to ensure nobody
        // tries using the tokens while we're updating them.
        pthread_rwlock_wrlock(&state->lock);

        // Now that we hold the write-lock, double check that the expired token that we used is still the one in the state
        // struct. If so, update it, if not, somebody else got here first.
        if (!strcmp(state->token, cached_token)) {
          int retval = handle_authentication(state, state->config.account_id, state->config.app_key);
          cache_auth(state);
          pthread_rwlock_unlock(&state->lock);
          return retval == B2FS_SUCCESS ? B2FS_NETWORK_TOKEN_ERROR : B2FS_NETWORK_ERROR;
        } else {
          pthread_rwlock_unlock(&state->lock);
          return B2FS_NETWORK_TOKEN_ERROR;
        }
      } else {
        return B2FS_NETWORK_ERROR;
      }
    }
  }

  // We shouldn't be able to get here if B2 returns a JSON object that fits the API docs, but the compiler doesn't
  // know that.
  return B2FS_NETWORK_ERROR;
}

int handle_authentication(b2fs_state_t *state, char *account_id, char *app_key) {
  CURL *curl = curl_easy_init();
  CURLcode res;
  char buf[B2FS_SMALL_GENERIC_BUFFER], based[B2FS_SMALL_GENERIC_BUFFER], final[B2FS_SMALL_GENERIC_BUFFER], *tmp = based;
  b2fs_string_t data;
  memset(&data, 0, sizeof(b2fs_string_t));

  // Create token to send for authentication.
  base64_encodestate encoder;
  base64_init_encodestate(&encoder);
  sprintf(buf, "%s:%s", account_id, app_key);
  tmp += base64_encode_block(buf, strlen(buf), tmp, &encoder);
  tmp += base64_encode_blockend(tmp, &encoder);
  *(--tmp) = '\0';
  sprintf(final, "Authorization: Basic %s", based);

  // Big, dirty, macro to handle all of the boilerplate cURL initialization stuff.
  // Note that we do not acquire the read-lock here, because this function will always either be
  // called with the write-lock held, or in a context where contention is impossible.
  INITIALIZE_LIBCURL(
      curl,
      "https://api.backblaze.com",
      "b2api/v1/b2_authorize_account",
      based,
      state->lock,
      "Authorization: Basic %s",
      data,
      receive_string,
      0);

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
      for (int i = 1; i < token_count; i++) {
        jsmntok_t *key = &tokens[i++], *value = &tokens[i];
        int len = value->end - value->start;

        if (jsmn_iskey(data.str, key, "authorizationToken")) {
          memset(state->token, 0, sizeof(char) * B2FS_TOKEN_LEN);
          memcpy(state->token, data.str + value->start, len);
        } else if (jsmn_iskey(data.str, key, "apiUrl")) {
          memset(state->api_url, 0, sizeof(char) * B2FS_TOKEN_LEN);
          memcpy(state->api_url, data.str + value->start, len);
        } else if (jsmn_iskey(data.str, key, "downloadUrl")) {
          memset(state->down_url, 0, sizeof(char) * B2FS_TOKEN_LEN);
          memcpy(state->down_url, data.str + value->start, len);
        } else if (!jsmn_iskey(data.str, key, "accountId")) {
          LOG_KEY(data.str, key, "authentication");
        }
      }
      free(data.str);

      // Validate and return!
      if (strlen(state->token) && strlen(state->api_url) && strlen(state->down_url)) {
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
      strncpy(state->token, data.str, B2FS_TOKEN_LEN - 1);
      state->token[B2FS_TOKEN_LEN - 1] = '\0';
      free(data.str);
      return B2FS_NETWORK_INTERN_ERROR;
    }
    return B2FS_SUCCESS;
  } else {
    // cURL error encountered. Don't know enough about this to predict why.
    // FIXME: Maybe add more detailed error handling here.
    strncpy(state->token, curl_easy_strerror(res), B2FS_TOKEN_LEN - 1);
    state->token[B2FS_TOKEN_LEN - 1] = '\0';
    curl_easy_cleanup(curl);
    return B2FS_NETWORK_ERROR;
  }
}

int init_file_entry(b2fs_file_entry_t *entry) {
  if (!entry) return B2FS_INVAL_ERROR;

  memset(entry, 0, sizeof(b2fs_file_entry_t));
  entry->chunkmap = create_bitmap();
  entry->chunks = create_keytree(NULL, NULL, intcmp, sizeof(int), sizeof(b2fs_file_chunk_t));
  entry->versions = create_keytree(NULL, destroy_file_version, rev_intcmp, sizeof(size_t), sizeof(b2fs_file_version_t));
  if (!entry->chunkmap || !entry->chunks) {
    if (entry->chunkmap) free(entry->chunkmap);
    if (entry->chunks) free(entry->chunks);
    return B2FS_NOMEM_ERROR;
  }

  return B2FS_SUCCESS;
}

int init_file_version(b2fs_file_version_t *version) {
  if (!version) return B2FS_INVAL_ERROR;

  memset(version, 0, sizeof(b2fs_file_version_t));
  version->should_delete = malloc(MEMBER_PTR_SIZE(b2fs_file_version_t, should_delete));
  version->hidden = malloc(MEMBER_PTR_SIZE(b2fs_file_version_t, hidden));
  version->live = malloc(MEMBER_PTR_SIZE(b2fs_file_version_t, live));
  version->synced = malloc(MEMBER_PTR_SIZE(b2fs_file_version_t, synced));
  *version->should_delete = 0;
  *version->hidden = 0;
  *version->live = 0;
  *version->synced = 0;
  if (version->should_delete && version->hidden && version->live && version->synced) {
    return B2FS_SUCCESS;
  } else {
    if (version->should_delete) free(version->should_delete);
    if (version->hidden) free(version->hidden);
    if (version->live) free(version->live);
    if (version->synced) free(version->synced);
    return B2FS_NOMEM_ERROR;
  }
}

int init_dir_entry(b2fs_dir_entry_t *entry) {
  if (!entry) return B2FS_INVAL_ERROR;

  memset(entry, 0, sizeof(b2fs_dir_entry_t));
  entry->directory = create_hash(sizeof(b2fs_hash_entry_t), destroy_hash_entry);
  entry->hidden = malloc(MEMBER_PTR_SIZE(b2fs_dir_entry_t, hidden));
  *entry->hidden = 0;

  if (entry->hidden && entry->directory) {
    return B2FS_SUCCESS;
  } else {
    if (entry->directory) hash_destroy(entry->directory);
    if (entry->hidden) free(entry->hidden);
    return B2FS_NOMEM_ERROR;
  }
}

void destroy_file_entry(void *voidarg) {
  b2fs_file_entry_t *entry = voidarg;
  keytree_destroy(entry->chunks);
  keytree_destroy(entry->versions);
  destroy_bitmap(entry->chunkmap);
  free(entry);
}

void destroy_file_version(void *voidarg) {
  b2fs_state_t *state = fuse_get_context()->private_data;
  b2fs_file_version_t *version = voidarg;

  if (version->should_delete && version->live) {
    // Do-While loop works as a conditional retry-loop if our auth token is expired.
    int do_again;
    do {
      CURL *curl = curl_easy_init();
      CURLcode res;
      char body[B2FS_SMALL_GENERIC_BUFFER];
      b2fs_string_t response;
      do_again = 0;
      memset(&response, 0, sizeof(b2fs_string_t));

      // Big, dirty, macro to handle all of the boilerplate cURL initialization stuff.
      // Acquire the read-lock to make sure we're using the right auth token and stuff.
      pthread_rwlock_rdlock(&state->lock);
      INITIALIZE_LIBCURL(
          curl,
          state->api_url,
          "b2api/b1/b2_delete_file_version",
          state->token,
          state->lock,
          "Authorization: %s",
          response,
          receive_string,
          1);
      pthread_rwlock_unlock(&state->lock);

      // Get file name.
      char *filename;
      assert(hash_get(state->id_mappings, version->version_id, &filename) == HASH_SUCCESS);
      hash_drop(state->id_mappings, version->version_id);

      // Set POST body.
      sprintf(body, "{\"fileName\":\"%s\",\"fileId\":\"%s\"}", filename, version->version_id);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);

      // Perform the request.
      if ((res = curl_easy_perform(curl)) == CURLE_OK) {
        long code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

        if (code == 200) {
          // No need to check response. Delete API just returns the sent data, and the API docs state that a 200 is sufficient
          // to know the file has been deleted.
          free(response.str);
        } else {
          // B2 returned an error.
          write_log(LEVEL_DEBUG, "B2FS: B2 returned an error code %ld with message: %s\n", code, response.str);

          // Attempt to handle the returned error.
          int retval = handle_b2_error(state, response.str, tok);

          // Clean up resources.
          free(response.str);
          memset(&response, 0, sizeof(b2fs_string_t));

          // Take necessary action based on error handling results.
          if (retval == B2FS_NETWORK_TOKEN_ERROR) do_again = 1;
          else write_log(LEVEL_DEBUG, "B2FS: B2 error went unhandled during version destructor.\n");
        }
      } else {
        // FIXME: This performs no error handling at the moment. Revisit this to decide what to do here.
        // Hate putting calls on multiple lines, but this is too long.
        write_log(LEVEL_DEBUG,
            "B2FS: cURL failed with error %s during destruction of file %s.\n",
            curl_easy_strerror(res), filename);
        write_log(LEVEL_ERROR, "B2FS: An unexpected network error was encountered during the deletion of file %s.\n", filename);
      }

      // We either succeeded or failed. Cleanup and return.
      curl_slist_free_all(headers);
      curl_easy_cleanup(curl);
    } while (do_again);
  }

  free(version->should_delete);
  free(version->hidden);
  free(version->live);
  free(version->synced);
}

void destroy_dir_entry(b2fs_dir_entry_t *entry) {
  hash_destroy(entry->directory);
  free(entry->hidden);
}

void destroy_hash_entry(void *voidarg) {
  b2fs_hash_entry_t *entry = voidarg;

  // Identify entry type and destroy.
  if (entry->type == TYPE_DIRECTORY) hash_destroy(entry->dir.directory);
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

hash_t *make_path(char **path_pieces, hash_t *base, b2fs_dir_entry_t *output) {
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
      init_dir_entry(&new_entry.dir);

      // Put it in the previous directory.
      hash_put(current, piece, &new_entry);
      hash_get(current, piece, &entry);
    } else if (entry.type != TYPE_DIRECTORY) {
      // An intermediate piece was not a directory. Give up and return.
      return NULL;
    }

    current = entry.dir.directory;
    if (output) memcpy(output, &entry.dir, sizeof(b2fs_dir_entry_t));
  }

  // Move final piece up to front of array for ease of access.
  path_pieces[0] = path_pieces[i - 1];

  // Return the directory containing the file.
  return current;
}

int find_path(char *path, hash_t *base, b2fs_hash_entry_t *buf, int honor_hidden) {
  char **path_pieces = split_path(path);
  int i = 0;
  hash_t *current = base;

  b2fs_hash_entry_t entry;
  for (char *piece = path_pieces[i++]; path_pieces[i - 1]; piece = path_pieces[i++]) {
    // Get the entry and perform basic validation.
    int retval = hash_get(current, piece, &entry);
    if (retval != HASH_SUCCESS) return B2FS_FS_NOENT_ERROR;
    else if (honor_hidden && entry.type == TYPE_DIRECTORY && *entry.dir.hidden) return B2FS_FS_NOENT_ERROR;
    else if (entry.type == TYPE_FILE && path_pieces[i]) return B2FS_FS_NOTDIR_ERROR;

    if (entry.type == TYPE_DIRECTORY) current = entry.dir.directory;
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
    int retval = find_path(parent_path, base, &entry, 1);
    free(parent_path);
    if (retval == B2FS_FS_NOTDIR_ERROR || entry.type != TYPE_DIRECTORY) {
      free(child_path);
      return -ENOTDIR;
    } else if (retval == B2FS_FS_NOENT_ERROR) {
      free(child_path);
      return -ENOENT;
    }
    parent = entry.dir.directory;
  } else {
    // We're inserting into the root directory.
    parent = base;
  }

  // Initialize new directory entry for insertion.
  b2fs_hash_entry_t created;
  created.type = type;
  if (type == TYPE_FILE) init_file_entry(&created.file);
  else init_dir_entry(&created.dir);

  // Insert the requested entry into the filesystem cache. B2 doesn't support empty files
  // or directories, so we just need to keep track of the fact that it exists until the
  // user decides to write some data.
  int retval = hash_put(parent, child_path, &created);
  if (retval == HASH_EXISTS_ERROR) {
    // The entry we tried to insert already exists. Obviously this may mean that the requested
    // path already exists, however, it could also mean that the user previously requested to
    // delete the path, but that we're set to hide files instead of actually deleting them.
    // Check which is the case.
    b2fs_hash_entry_t entry;
    hash_get(parent, child_path, &entry);
    if (type == TYPE_FILE) {
      b2fs_file_version_t version;

      // Get most recent version of file.
      keytree_iterator_t *it = keytree_iterate_start(entry.file.versions, NULL);
      assert(keytree_iterate_next(it, NULL, &version) == KEYTREE_SUCCESS);
      keytree_iterate_stop(it);

      if (!*entry.dir.hidden) {
        destroy_file_entry(&created.file);
        return -EEXIST;
      }
    } else {
      if (*entry.dir.hidden) {
        // Mark directory as no longer hidden and delete .b2fs_hidefile on B2 to persist.
        *entry.dir.hidden = 0;

        b2fs_hash_entry_t hide_entry;
        hash_t *directory = entry.dir.directory;
        assert(hash_get(directory, ".b2fs_hidefile", &hide_entry) == HASH_SUCCESS);

        // FIXME: Visit this in the future when b2_sync_versions has been written.
        // Currently ignores return value of b2_sync_versions, but we need to verify
        // that this won't leave us in an unacceptable state.
        b2_sync_versions(&hide_entry.file, path);
        destroy_file_entry(&hide_entry);
      } else {
        // Directory actually exists.
        destroy_dir_entry(&created.dir);
        return -EEXIST;
      }
    }
  } else if (retval != HASH_SUCCESS) {
    // Hash reported an unexpected error. Most likely means that we're out of memory, or
    // code is in an invalid state. Report a generic IO error for now.
    write_log(LEVEL_DEBUG, "B2FS: Hash returned an unexpected error in internal_make...");
    return -EIO;
  }

  // If we've gotten to this point, we've either successfully created a directory
  // or we've ensured that the file we're creating either doesn't exist, or is currently
  // hidden. If we're working with a file, we need to insert a file version into the
  // version tree.
  // FIXME: Slight caveat here. As we're just creating the file, and don't know what it's
  // contents will be, we can't get a file-id from B2, and as such this entry will be
  // incomplete. In downstream functions, like b2fs_unlink, we'll need to sync with B2
  // to get the information from B2.
  if (type == TYPE_FILE) {
    b2fs_hash_entry_t entry;
    b2fs_file_version_t version;
    init_file_version(&version);
    hash_get(parent, child_path, &entry);

    size_t timestamp = (size_t) time(NULL);
    keytree_insert(entry.file.versions, &timestamp, &version);
  }

  return B2FS_SUCCESS;
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
  if (!tmpdir) return B2FS_ERROR;

  // Open cache file.
  sprintf(path, "%s/b2fs_cache.txt", tmpdir);
  FILE *cache_in = fopen(path, "r");

  // Read the cached info in.
  if (cache_in) {
    int success;
    fscanf(cache_in, "%s\n%s\n%s", b2_info->token, b2_info->api_url, b2_info->down_url);
    success = strlen(b2_info->token) && strlen(b2_info->api_url) && strlen(b2_info->down_url);
    return success ? B2FS_SUCCESS : B2FS_ERROR;
  } else {
    return B2FS_ERROR;
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
        else return B2FS_ERROR;
      } else {
        return B2FS_ERROR;
      }
    }
    return B2FS_SUCCESS;
  } else {
    return B2FS_ERROR;
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

void dereference_and_destroy(void *destroyed) {
  free(*(char **) destroyed);
}

void print_usage(int intentional) {
  puts("./b2fs <--config | YAML file to read config from> <--mount | Mount point>");
  exit(intentional ? EXIT_SUCCESS : EXIT_FAILURE);
}
