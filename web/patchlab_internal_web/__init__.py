"""PatchLab Internal web front end: an optional browser UI for the PatchLab Internal CLI.

Separate from the core package on purpose: the core never imports it, and it
drives the core only through `python -m patchlab_internal ...` processes and the
report files they write. Enable it with `patchlab-internal setup --web` or
`patchlab-internal web enable`, then start it with `patchlab-internal web`.
"""

__version__ = "0.1.0"


def serve(settings, host=None, port=None, open_browser=False, allow_remote=False, estate=None) -> int:
    from .server import serve as _serve
    return _serve(settings, host=host, port=port, open_browser=open_browser, allow_remote=allow_remote,
                  estate=estate)
