/* SPDX-License-Identifier: MIT */
#include <stdlib.h>
#include <string.h>

#include "urlkit.h"

static char *copy_string(const char *s) {
  size_t n = strlen(s) + 1;
  char *copy = (char *) malloc(n);

  if (copy)
    memcpy(copy, s, n);
  return copy;
}

static void free_pair(uk_pair_t *pair) {
  free(pair->name);
  free(pair->value);
  free(pair);
}

bool uk_list_add(uk_list_t *list, const char *name, const char *value) {
  uk_pair_t *pair = (uk_pair_t *) calloc(1, sizeof (*pair));
  uk_pair_t **tail;

  if (!pair)
    return false;
  pair->name = copy_string(name);
  pair->value = copy_string(value);
  if (!pair->name || !pair->value) {
    free_pair(pair);
    return false;
  }

  /* Append, so pairs come back out in the order they were added. */
  for (tail = &list->head; *tail; tail = &(*tail)->next)
    ;
  *tail = pair;
  return true;
}

const char *uk_list_get(const uk_list_t *list, const char *name) {
  const uk_pair_t *pair;

  for (pair = list->head; pair; pair = pair->next) {
    if (strcmp(pair->name, name) == 0)
      return pair->value;
  }
  return NULL;
}

bool uk_list_remove(uk_list_t *list, const char *name) {
  uk_pair_t **link;

  for (link = &list->head; *link; link = &(*link)->next) {
    if (strcmp((*link)->name, name) == 0) {
      uk_pair_t *pair = *link;

      *link = pair->next;
      free_pair(pair);
      return true;
    }
  }
  return false;
}

void uk_list_clear(uk_list_t *list) {
  while (list->head) {
    uk_pair_t *next = list->head->next;

    free_pair(list->head);
    list->head = next;
  }
}
