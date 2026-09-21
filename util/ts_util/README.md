# `ts_util`

Various utilities that don't belong anywhere else.

`utils` packages tend to get bloated and become a dumping ground for anything that doesn't otherwise
have a clear home. 

Rules of thumb:

- Avoid putting code here unless it's _actively_ (operative word -- right now, not eventually in 
  theory) inconvenient not to. 
- Consider whether there's somewhere else it belongs better: treat this as a last resort when you
  must share code that doesn't have an extant functional grouping (and it doesn't make sense to make 
  a new crate for it). PRs cleaning up unused functionality in this crate or refactoring it to a 
  place it fits better are greatly appreciated and encouraged.
- Avoid the `std` and `tokio` OS platform layers. Don't embed networking, files, process spawning, 
  etc. inside functions in this crate: let the user provide this functionality as arguments via
  `Read`/`Write` and similar traits. If platform I/O is necessary for your function, it probably 
  doesn't belong here.
