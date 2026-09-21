use core::sync::atomic::{AtomicUsize, Ordering};

use rustler::{LocalPid, sys::ErlNifPid};

/// Wrapper around [`LocalPid`] providing atomic load/store.
pub struct AtomicPid(AtomicUsize);

static_assertions::assert_eq_size!(usize, ErlNifPid);

impl AtomicPid {
    /// Get the current pid.
    pub fn load(&self, ordering: Ordering) -> LocalPid {
        pid_from_usize(self.0.load(ordering))
    }

    /// Set the pid.
    pub fn store(&self, pid: LocalPid, ordering: Ordering) {
        self.0.store(pid_to_usize(pid), ordering)
    }
}

fn pid_to_usize(pid: LocalPid) -> usize {
    // SAFETY: `ErlNifPid` is a `usize` internally.
    unsafe { core::mem::transmute::<ErlNifPid, usize>(*pid.as_c_arg()) }
}

fn pid_from_usize(pid: usize) -> LocalPid {
    // SAFETY: `ErlNifPid` is a `usize` internally.
    LocalPid::from_c_arg(unsafe { core::mem::transmute::<usize, ErlNifPid>(pid) })
}

impl From<LocalPid> for AtomicPid {
    fn from(value: LocalPid) -> Self {
        AtomicPid(AtomicUsize::new(pid_to_usize(value)))
    }
}

impl From<&AtomicPid> for LocalPid {
    fn from(value: &AtomicPid) -> Self {
        value.load(Ordering::SeqCst)
    }
}

impl From<AtomicPid> for LocalPid {
    fn from(mut value: AtomicPid) -> Self {
        let pid = *value.0.get_mut();
        pid_from_usize(pid)
    }
}
