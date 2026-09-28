/* SPDX-License-Identifier: MIT
 *
 * Regression tests for urlkit, used by the PatchLab Internal example.
 *
 * Output is TAP (https://testanything.org) so PatchLab Internal can compare results
 * test-by-test between the baseline and the patched build.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "urlkit.h"

static int test_num = 0;
static int failures = 0;

static void ok(int cond, const char *desc) {
  test_num++;
  if (!cond)
    failures++;
  printf("%s %d - %s\n", cond ? "ok" : "not ok", test_num, desc);
}

static void test_client_defaults(void) {
  /* Start from dirty memory so a partial memset in the defaults is caught. */
  uk_client_t *client = (uk_client_t *) malloc(sizeof (uk_client_t));

  memset(client, 0x5A, sizeof (*client));
  uk_client_defaults(client);
  ok(strcmp(client->user_agent, "urlkit/1.0") == 0, "client: default user agent");
  ok(client->timeout_seconds == 30, "client: default timeout");
  ok(client->max_retries == 3, "client: default retries");
  ok(client->verify_tls, "client: TLS verification on by default");
  ok(client->token[0] == '\0', "client: token starts empty");
  ok(client->base_url[0] == '\0', "client: base URL starts empty");

  uk_client_set_token(client, "TOKEN123");
  ok(strcmp(client->token, "TOKEN123") == 0, "client: set token");
  free(client);
}

static void test_list(void) {
  uk_list_t list = { NULL };

  uk_list_add(&list, "q", "first");
  uk_list_add(&list, "page", "2");
  uk_list_add(&list, "sort", "name");
  ok(uk_list_get(&list, "page") && strcmp(uk_list_get(&list, "page"), "2") == 0, "list: lookup by name");
  ok(uk_list_get(&list, "missing") == NULL, "list: unknown name returns NULL");
  ok(strcmp(list.head->name, "q") == 0 && strcmp(list.head->next->name, "page") == 0,
     "list: keeps insertion order");

  ok(uk_list_remove(&list, "page"), "list: remove finds the pair");
  ok(uk_list_get(&list, "page") == NULL, "list: removed pair is gone");
  ok(uk_list_get(&list, "sort") != NULL, "list: remove keeps the following pairs");
  ok(!uk_list_remove(&list, "page"), "list: removing twice reports not found");

  uk_list_clear(&list);
  ok(list.head == NULL, "list: clear empties the list");
}

static void test_encode(void) {
  char out[64];
  char *exact;

  ok(uk_encode("hello", out, sizeof (out)) == 5 && strcmp(out, "hello") == 0, "encode: plain text unchanged");
  ok(uk_encode("a b&c=d", out, sizeof (out)) >= 0 && strcmp(out, "a%20b%26c%3Dd") == 0,
     "encode: reserved characters escaped");
  ok(uk_encode("-._~", out, sizeof (out)) >= 0 && strcmp(out, "-._~") == 0, "encode: unreserved marks kept");
  ok(uk_encode("caf\xc3\xa9", out, sizeof (out)) >= 0 && strcmp(out, "caf%C3%A9") == 0,
     "encode: UTF-8 bytes escaped");
  ok(uk_encode("", out, sizeof (out)) == 0 && out[0] == '\0', "encode: empty string");
  ok(uk_encode("a b", out, 3) == -1, "encode: too small a buffer is refused");

  /* Exactly the text's length, with no room for the NUL: must be refused,
   * not written one byte past the end. */
  exact = (char *) malloc(4);
  ok(uk_encode("abcd", exact, 4) == -1, "encode: refuses when only the NUL doesn't fit");
  free(exact);
}

static void test_query_build(void) {
  uk_list_t params = { NULL };
  char out[64];

  uk_list_add(&params, "q", "hello world");
  uk_list_add(&params, "page", "2");
  ok(uk_query_build(&params, out, sizeof (out)) >= 0 && strcmp(out, "q=hello%20world&page=2") == 0,
     "query: pairs joined and encoded");
  ok(uk_query_build(&params, out, 10) == -1, "query: too small a buffer is refused");
  uk_list_clear(&params);

  ok(uk_query_build(&params, out, sizeof (out)) == 0 && out[0] == '\0', "query: no params gives empty string");
}

static void test_headers(void) {
  uk_client_t client;
  uk_list_t headers = { NULL };
  const char *auth;

  uk_client_defaults(&client);
  uk_client_set_token(&client, "TOKEN123");

  ok(uk_request_headers(&client, UK_LOGIN, &headers), "login: headers built");
  ok(uk_list_get(&headers, "User-Agent") && strcmp(uk_list_get(&headers, "User-Agent"), "urlkit/1.0") == 0,
     "login: user agent header");
  ok(uk_list_get(&headers, "Authorization") == NULL, "login: no Authorization header");
  uk_list_clear(&headers);

  ok(uk_request_headers(&client, UK_GET_PROFILE, &headers), "get_profile: headers built");
  auth = uk_list_get(&headers, "Authorization");
  ok(auth && strcmp(auth, "Bearer TOKEN123") == 0, "get_profile: bearer token header");
  ok(uk_list_get(&headers, "Accept") && strcmp(uk_list_get(&headers, "Accept"), "application/json") == 0,
     "get_profile: accepts JSON");
  uk_list_clear(&headers);

  ok(strcmp(uk_action_name(UK_LIST_ITEMS), "list_items") == 0, "actions: names");
}

int main(void) {
  printf("TAP version 13\n");

  test_client_defaults();
  test_list();
  test_encode();
  test_query_build();
  test_headers();

  printf("1..%d\n", test_num);
  return failures ? 1 : 0;
}
