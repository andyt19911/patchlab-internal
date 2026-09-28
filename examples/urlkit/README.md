# urlkit: PatchLab Internal's Linux example

urlkit is a small C99 library for building HTTP API requests: an ordered
name/value list, RFC 3986 percent-encoding, query strings, and request headers
with bearer-token handling. It was written for PatchLab Internal as the application
under test, and is original code under the MIT licence (see `LICENSE`).

It deliberately ships with two real bugs, the kind that turn up in production
C code, so the example has something genuine to fix:

- `uk_client_defaults()` clears the struct with `memset(client, 0, sizeof (client))`,
  which is the size of the *pointer*, so `token` and `base_url` keep whatever was
  in memory. The compiler warns about it, and two unit tests fail.
- `uk_encode()` checks `used + 1 > outlen` instead of `>=`, so text that exactly
  fills the buffer leaves no room for the terminating NUL, which is then written
  one byte past the end. One unit test fails, and AddressSanitizer reports a
  heap-buffer-overflow.

| Patch | What it does | Expected verdict |
|---|---|---|
| `patches/fix-defaults-and-bounds.patch` | Fixes both bugs | PASS: fixes 3 failing tests, the sanitizer report and the warning |
| `patches/always-send-auth-header.patch` | A plausible-looking change that also sends the token on login | FAIL: regresses `login: no Authorization header` |
| `patches/simulate-broken-os-update.sh` | Breaks the OS underneath the app (removes a shared library, edits `/etc`) | FAIL, and the planned rollback fails too |

Layout: `src/` is the library (deployed to `/opt/app`), `tests/test_urlkit.c`
prints TAP so PatchLab Internal compares results test by test, and `patchlab.toml`
defines the build, unit-test, memory-safety and compiler-warning checks.
