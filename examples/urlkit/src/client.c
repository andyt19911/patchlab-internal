/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <string.h>

#include "urlkit.h"

void uk_client_defaults(uk_client_t *client) {
  memset(client, 0, sizeof (client));

  snprintf(client->user_agent, sizeof (client->user_agent), "urlkit/1.0");
  client->timeout_seconds = 30;
  client->max_retries = 3;
  client->verify_tls = true;
}

void uk_client_set_token(uk_client_t *client, const char *token) {
  snprintf(client->token, sizeof (client->token), "%s", token);
}

const char *uk_action_name(uk_action_t action) {
  switch (action) {
    case UK_LOGIN:
      return "login";
    case UK_GET_PROFILE:
      return "get_profile";
    case UK_LIST_ITEMS:
      return "list_items";
  }
  return "unknown";
}

bool uk_request_headers(const uk_client_t *client, uk_action_t action, uk_list_t *headers) {
  char buffer[UK_FIELD_MAX + 16];

  if (!uk_list_add(headers, "User-Agent", client->user_agent))
    return false;
  if (!uk_list_add(headers, "Accept", "application/json"))
    return false;

  /* The login request is what obtains the token, so it never carries one. */
  if (action != UK_LOGIN) {
    snprintf(buffer, sizeof (buffer), "Bearer %s", client->token);
    if (!uk_list_add(headers, "Authorization", buffer))
      return false;
  }
  return true;
}
