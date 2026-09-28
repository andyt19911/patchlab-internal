/* SPDX-License-Identifier: MIT */
#include "urlkit.h"

/* RFC 3986 unreserved characters pass through; everything else is %XX. */
static bool unreserved(unsigned char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
         c == '-' || c == '.' || c == '_' || c == '~';
}

int uk_encode(const char *in, char *out, size_t outlen) {
  static const char hex[] = "0123456789ABCDEF";
  const unsigned char *p;
  size_t used = 0;

  if (outlen == 0)
    return -1;

  for (p = (const unsigned char *) in; *p; p++) {
    if (unreserved(*p)) {
      if (used + 1 > outlen)
        return -1;
      out[used++] = (char) *p;
    } else {
      if (used + 3 > outlen)
        return -1;
      out[used++] = '%';
      out[used++] = hex[*p >> 4];
      out[used++] = hex[*p & 0x0F];
    }
  }
  out[used] = '\0';
  return (int) used;
}

int uk_query_build(const uk_list_t *params, char *out, size_t outlen) {
  const uk_pair_t *pair;
  size_t used = 0;
  int n;

  if (outlen == 0)
    return -1;
  out[0] = '\0';

  for (pair = params->head; pair; pair = pair->next) {
    if (pair != params->head) {
      if (used + 1 >= outlen)
        return -1;
      out[used++] = '&';
    }
    n = uk_encode(pair->name, out + used, outlen - used);
    if (n < 0)
      return -1;
    used += (size_t) n;

    if (used + 1 >= outlen)
      return -1;
    out[used++] = '=';

    n = uk_encode(pair->value, out + used, outlen - used);
    if (n < 0)
      return -1;
    used += (size_t) n;
  }
  out[used] = '\0';
  return (int) used;
}
