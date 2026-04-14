# ts_dataplane

The packet processing data plane.

The core of the data plane is synchronous and non-blocking, so that it can be wrapped in
the user's choice of sync/async runtimes.
