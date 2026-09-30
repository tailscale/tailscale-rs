use std::ffi::c_char;

use crate::{keys::persisted_key_state, util};

/// Tailscale configuration.
///
/// This struct is safe to zero-initialize, in which case default values will be used.
/// You _must_ actually zero-initialize this struct in this case (`struct ts_config config = {0};`);
/// an uninitialized declaration (`struct ts_config config;`) is insufficient and may invoke UB.
///
/// On the Rust side, the [`Default`] instance for this type is equivalent to a C-side zero-
/// init.
#[derive(Default)]
#[repr(C)]
pub struct config<'a> {
    /// The control server URL to use.
    ///
    /// May be `NULL` to use the default value.
    pub control_server_url: *const c_char,

    /// The hostname to use. This will be the device's MagicDNS name, if it's available.
    ///
    /// May be `NULL` to use the default (the OS-reported hostname).
    pub hostname: *const c_char,

    /// An array of tags to be requested.
    ///
    /// Use `NULL` as the sentinel for the end of the array.
    ///
    /// May be `NULL` to indicate that no tags are requested.
    pub tags: *const *const c_char,

    /// The client name to report to the control server. This is reported as `Hostinfo.App`.
    ///
    /// May be `NULL` to use the default (`ts_ffi`).
    pub client_name: *const c_char,

    /// The key state to use.
    ///
    /// If `NULL`, ephemeral key state is generated.
    pub key_state: Option<&'a mut persisted_key_state>,

    /// Whether to register this node as ephemeral.
    ///
    /// Ephemeral nodes are removed from the tailnet after being offline for a brief period.
    pub ephemeral: bool,
}

impl config<'_> {
    /// Convert this config into a [`tailscale::Config`].
    ///
    /// # Safety
    ///
    /// All string fields (including elements of `tags`, if any) must be either null or
    /// NUL-terminated and valid for reads up to the nul-terminator.
    ///
    /// The `tags` field must be either null or a pointer to a contiguous array of valid,
    /// aligned, NUL-terminated strings, fully contained in a single
    /// [allocation](https://doc.rust-lang.org/std/ptr/index.html#allocation). A null
    /// pointer must be used to terminate the array.
    pub unsafe fn to_ts_config(&self) -> tailscale::Config {
        let mut cfg = tailscale::Config::default();

        // SAFETY: validity ensured by preconditions
        let ctrl_url = unsafe { util::str(self.control_server_url) }.and_then(|u| u.parse().ok());

        if let Some(u) = ctrl_url {
            cfg.control_server_url = u;
        }

        // SAFETY: validity ensured by preconditions
        if let Some(hostname) = unsafe { util::str(self.hostname) } {
            cfg.requested_hostname = Some(hostname.to_string());
        }

        // SAFETY: validity ensured by preconditions
        cfg.client_name = Some(
            unsafe { util::str(self.client_name) }
                .unwrap_or("ts_ffi")
                .to_owned(),
        );

        if let Some(key_state) = &self.key_state {
            cfg.key_state = (&**key_state).into();
        }

        // SAFETY: by preconditions and function termination on null tag
        cfg.requested_tags = unsafe {
            load_sentinel_array(self.tags, |&tag| {
                if tag.is_null() {
                    return None;
                };

                match util::str(tag) {
                    Some(tag_str) => Some(Some(tag_str.to_owned())),
                    None => {
                        tracing::error!("skipping invalid requested tag");
                        Some(None)
                    }
                }
            })
        }
        .collect();

        cfg.ephemeral = self.ephemeral;

        cfg
    }
}

/// Iterate a raw pointer `ary` as a C-style sentinel-terminated array.
///
/// Starting at `ary`, increment `ary` (strides of `size_of::<T>()`) until the pointee does
/// not satisfy `elem_txfm`, a `filter_map`-style simultaneous predicate-and-transform.
///
/// # Safety
///
/// `ary` must be either null or follow the rules for [`std::slice::from_raw_parts`], except
/// that it needn't have a definite length known before calling this function. The extents
/// of `ary` are defined by `elem_txfm`: the first element that returns `None` under
/// `elem_txfm` is the final (sentinel) element of the array (excluded here from the
/// returned iterated elements, but part of the memory extents).
///
/// The extents of `ary` must be contiguous and aligned, and its elements must be valid for
/// reads and properly-initialized. They must obey rust mutability rules -- no
/// mutations to the extents of `ary` are permitted for the lifetime of the returned
/// iterator.
///
/// Note that this definition implies a strong safety condition on the definition
/// of `elem_txfm`: it defines what memory is accessed by this function and must not permit
/// iteration beyond valid bounds.
unsafe fn load_sentinel_array<'t, T, It>(
    mut ary: *const T,
    elem_txfm: impl Fn(&T) -> Option<It> + 't,
) -> impl Iterator<Item = It::Item>
where
    T: 't,
    It: IntoIterator,
{
    std::iter::from_fn(move || {
        if ary.is_null() {
            return None;
        }

        // SAFETY: ref-validity ensured by preconditions, non-nullity by above check
        let it = match elem_txfm(unsafe { ary.as_ref().unwrap() }) {
            Some(u) => u,
            None => {
                return None;
            }
        };

        // SAFETY: ensured by preconditions
        ary = unsafe { ary.offset(1) };

        Some(it)
    })
    .flatten()
}

#[cfg(test)]
mod test {
    use std::{ffi::CString, ptr::null};

    use super::*;

    #[test]
    fn sentinel_array() {
        let mut v = unsafe { load_sentinel_array::<u8, _>(null(), |_| Option::<[u8; 1]>::None) };
        assert!(v.next().is_none());

        let ary = [0u8, 1, 2, 3, 4, 5, 6, 128, 32];

        let mut v =
            unsafe { load_sentinel_array(&ary as *const u8, |_elt| Option::<Option<u8>>::None) };
        assert!(v.next().is_none());

        let v = unsafe {
            load_sentinel_array(
                &ary as *const u8,
                |&elt| {
                    if elt < 10 { Some([elt]) } else { None }
                },
            )
        }
        .collect::<Vec<_>>();
        assert!(!v.is_empty());
        assert_eq!(v, ary[..=6].to_vec());
    }

    #[test]
    fn tags() {
        let tag_foo = CString::new("foo").unwrap();
        let tag_bar = CString::new("bar").unwrap();

        let config = config {
            tags: &[tag_foo.as_ptr(), tag_bar.as_ptr(), null()] as *const *const c_char,
            ..Default::default()
        };

        let cfg = unsafe { config.to_ts_config() };
        assert_eq!(cfg.requested_tags, vec!["foo", "bar"]);
    }
}
