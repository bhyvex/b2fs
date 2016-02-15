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

/*----- Local Includes -----*/

#include "b64/cencode.h"

/*----- Numerical Constants -----*/

#define B2FS_SUCCESS 0x00
#define B2FS_GENERIC_ERROR -0x01
#define B2FS_GENERIC_NETWORK_ERROR -0x02
#define B2FS_NOMEM -0x04

#define B2FS_ACCOUNT_ID_LEN 16
#define B2FS_APP_KEY_LEN 64
#define B2FS_SMALL_GENERIC_BUFFER 128

// So the preprocessor won't complain.
#undef FUSE_USE_VERSION
#define FUSE_USE_VERSION 30

/*----- Macro Declarations -----*/

#ifdef DEBUG

#define write_log(level, ...)                                     \
  do {                                                            \
    printf(__VA_ARGS__);                                          \
  } while (0);

#elif INFO

#define write_log(level, ...)                                     \
  do {                                                            \
    if (level == LEVEL_INFO) printf(__VA_ARGS__)                  \
    else if (level == LEVEL_ERROR) fprintf(stderr, __VA_ARGS__);  \
  } while (0);

#else

#define write_log(level, ...)                                     \
  do {                                                            \
    if (level == LEVEL_ERROR) fprintf(stderr, __VA_ARGS__);       \
  } while (0);

#endif

/*----- Type Declarations -----*/

typedef struct b2_authentication {
  char account_id[B2FS_ACCOUNT_ID_LEN];
  char app_key[B2FS_APP_KEY_LEN];
} b2_authentication_t;

typedef enum b2fs_loglevel {
  LEVEL_DEBUG,
  LEVEL_INFO,
  LEVEL_ERROR
} b2fs_loglevel_t;

/*----- Local Function Declarations -----*/

// Filesystem Functions.

void *b2fs_init(struct fuse_conn_info *info);
void b2fs_destroy(void *userdata);
int b2fs_getattr(const char *path, struct stat *statbuf);
int b2fs_readlink(const char *path, char *buf, size_t size);
int b2fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *info);
int b2fs_mknod(const char *path, mode_t mode, dev_t rdev);
int b2fs_mkdir(const char *path, mode_t mode);
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
int b2fs_access(const char *path, mode_t mode);

// Network Functions.

size_t receive_string(void *data, size_t size, size_t nmembers, void *voidarg);

// Helper Functions.

int parse_config(b2_authentication_t *auth, char *config_file);
int attempt_authentication(b2_authentication_t *auth, char *auth_token);
void print_usage(int intentional);

/*----- Evil Globals -----*/

const char *base = "https://api.backblaze.com/b2api/v1";

/*----- Local Function Implementations -----*/

int main(int argc, char **argv) {
  int c, index, retval;
  b2_authentication_t auth;
  char *config = "b2fs.yml", *mount_point = "~/b2", auth_token[B2FS_SMALL_GENERIC_BUFFER];
  struct option long_options[] = {
    {"config", required_argument, 0, 'c'},
    {"mount", required_argument, 0, 'm'},
    {0, 0, 0, 0}
  };

  // Get CLI options.
  while ((c = getopt_long(argc, argv, "c:", long_options, &index))) {
    switch (c) {
      case 'c':
        config = optarg;
      case 'm':
        mount_point = optarg;
      default:
        print_usage(0);
    }
  }

  // Get auth information from the config file.
  if (parse_config(&auth, config)) {
    write_log(LEVEL_ERROR, "B2FS: Malformed config file.\n");
  }

  // Attempt to grab authentication token from B2.
  curl_global_init(CURL_GLOBAL_DEFAULT);
  retval = attempt_authentication(&auth, auth_token);
  if (retval == B2FS_GENERIC_NETWORK_ERROR) {
    write_log(LEVEL_ERROR, "B2FS: Authentication failed. Given reason: %s\n", auth_token);
  } else if (retval == B2FS_GENERIC_ERROR) {
    write_log(LEVEL_ERROR, "B2FS: Failed to initialize network.\n");
  }

  // We are authenticated and have a valid token. Now the real work begins.
  // TODO: Write the real filesystem logic.
}

// TODO: Implement this function.
void *b2fs_init(struct fuse_conn_info *info) {
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
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *info) {
  return -ENOTSUP;
}

int b2fs_mknod(const char *path, mode_t mode, dev_t rdev) {
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_mkdir(const char *path, mode_t mode) {
  return -ENOTSUP;
}

int b2fs_symlink(const char *from, const char *to) {
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
  return -ENOTSUP;
}

int b2fs_chmod(const char *path, mode_t mode) {
  return -ENOTSUP;
}

int b2fs_chown(const char *path, uid_t uid, gid_t gid) {
  return -ENOTSUP;
}

// TODO: Implement this function.
int b2fs_truncate(const char *path, off_t size) {
  return -ENOTSUP;
}

int b2fs_utime(const char *path, struct utimbuf *buf) {
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

int b2fs_fsync(const char *path, int crap, struct fuse_file_info *info) {
  return -ENOTSUP;
}

int b2fs_access(const char *path, mode_t mode) {
  return -ENOTSUP;
}

size_t receive_string(void *data, size_t size, size_t nmembers, void *voidarg) {
  char *recvbuf = malloc(sizeof(char) * ((size * nmembers) + 1));
  char **output = voidarg;
  memcpy(recvbuf, data, size * nmembers);
  *(recvbuf + (size * nmembers)) = '\0';
  *output = recvbuf;
}

int parse_config(b2_authentication_t *auth, char *config_file) {
  FILE *config = fopen(config_file, "r");
  char keybuf[B2FS_SMALL_GENERIC_BUFFER], valbuf[B2FS_SMALL_GENERIC_BUFFER];
  memset(auth, 0, sizeof(b2_authentication_t));

  if (config) {
    for (int i = 0; i < 2; i++) {
      fscanf(config, "%s: %s\n", keybuf, valbuf);

      if (!strcmp(keybuf, "account_id")) {
        strcpy(auth->account_id, valbuf);
      } else if (!strcmp(keybuf, "app_key")) {
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

int attempt_authentication(b2_authentication_t *auth, char *auth_token) {
  CURL *curl;
  CURLcode res;

  curl = curl_easy_init();
  if (curl) {
    char urlbuf[B2FS_SMALL_GENERIC_BUFFER], conversionbuf[B2FS_SMALL_GENERIC_BUFFER];
    char based[B2FS_SMALL_GENERIC_BUFFER], final[B2FS_SMALL_GENERIC_BUFFER];
    char *tmp = based, *data = NULL;
    
    // Set URL for request.
    sprintf(urlbuf, "%s/b2_authorize_account", base);
    curl_easy_setopt(curl, CURLOPT_URL, urlbuf);

    // Create token to send for authentication.
    base64_encodestate state;
    base64_init_encodestate(&state);
    sprintf(conversionbuf, "%s:%s", auth->account_id, auth->app_key);
    tmp += base64_encode_block(conversionbuf, strlen(conversionbuf), tmp, &state);
    tmp += base64_encode_blockend(tmp, &state);
    *tmp = '\0';
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
      // Copy data into output buffer and return.
      assert(strlen(data) < B2FS_SMALL_GENERIC_BUFFER);
      strcpy(auth_token, data);
      return B2FS_SUCCESS;
    } else {
      strcpy(auth_token, curl_easy_strerror(res));
      return B2FS_GENERIC_NETWORK_ERROR;
    }
  } else {
    return B2FS_GENERIC_ERROR;
  }
}

void print_usage(int intentional) {
  puts("./b2fs <--config | YAML file to read config from> <--mount | Mount point>");
  exit(intentional ? EXIT_SUCCESS : EXIT_FAILURE);
}
