/* SPDX-License-Identifier: MIT
 *
 * urlkit: a small C99 library for building HTTP API requests (query strings
 * and headers). Written as the application under test in PatchLab Internal's Linux
 * example; see ../README.md.
 */
#ifndef URLKIT_H
#define URLKIT_H

#include <stdbool.h>
#include <stddef.h>

#define UK_FIELD_MAX 128

/* An ordered list of name/value pairs: query parameters or headers. */
typedef struct uk_pair {
  char *name;
  char *value;
  struct uk_pair *next;
} uk_pair_t;

typedef struct {
  uk_pair_t *head;
} uk_list_t;

typedef struct {
  int timeout_seconds;
  int max_retries;
  bool verify_tls;
  char base_url[UK_FIELD_MAX];
  char user_agent[UK_FIELD_MAX];
  char token[UK_FIELD_MAX];
} uk_client_t;

typedef enum {
  UK_LOGIN,
  UK_GET_PROFILE,
  UK_LIST_ITEMS
} uk_action_t;

/* list.c */
bool uk_list_add(uk_list_t *list, const char *name, const char *value);
const char *uk_list_get(const uk_list_t *list, const char *name);
bool uk_list_remove(uk_list_t *list, const char *name);
void uk_list_clear(uk_list_t *list);

/* encode.c
 *
 * Both functions write a NUL-terminated string to `out` and return its
 * length, or -1 if it (with the terminating NUL) doesn't fit in `outlen`
 * bytes. */
int uk_encode(const char *in, char *out, size_t outlen);
int uk_query_build(const uk_list_t *params, char *out, size_t outlen);

/* client.c */
void uk_client_defaults(uk_client_t *client);
void uk_client_set_token(uk_client_t *client, const char *token);
const char *uk_action_name(uk_action_t action);
bool uk_request_headers(const uk_client_t *client, uk_action_t action, uk_list_t *headers);

#endif
