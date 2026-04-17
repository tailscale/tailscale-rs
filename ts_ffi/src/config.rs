use std::ffi::c_char;

use crate::{keys::node_key_state, util};

/// Tailscale configuration.
///
/// This struct is safe to zero-initialize, in which case default values will be used.
/// You _must_ actually zero-initialize this struct in this case (`struct ts_config config = {0};`);
/// an uninitialized declaration (`struct ts_config config;`) is insufficient and may invoke UB.
#[derive(Default)]
#[repr(C)]
pub struct config<'a> {
    /// The control server URL to use.
    ///
    /// May be `NULL` to use the default value.
    pub control_server_url: *const c_char,

    /// The hostname to use.
    ///
    /// May be `NULL` to use the default (the OS-reported hostname).
    pub hostname: *const c_char,

    /// An array of tags to be requested.
    ///
    /// Use `NULL` as the sentinel for the end of the array.
    ///
    /// May be `NULL` to indicate that no tags are requested.
    pub tags: *const *const c_char,

    /// The client name to report to the control server.
    ///
    /// May be `NULL` to use the default (`ts_ffi`).
    pub client_name: *const c_char,

    /// The key state to use.
    ///
    /// If `NULL`, ephemeral key state is generated.
    pub key_state: Option<&'a mut node_key_state>,
}

impl config<'_> {
    /// Convert this config into a [`tailscale::Config`].
    ///
    /// # Safety
    ///
    /// All string fields (including elements of `tags`, if any) must be either null or
    /// nul-terminated and valid for reads up to the nul-terminator.
    ///
    /// The `tags` field must be either null or an aligned pointer to an array of valid,
    /// nul-terminated strings, fully contained in a single
    /// [allocation](https://doc.rust-lang.org/std/ptr/index.html#allocation). A null pointer must
    /// be used to terminate the array.
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
        if let Some(client_name) = unsafe { util::str(self.client_name) } {
            cfg.client_name = Some(client_name.to_string());
        }

        if let Some(key_state) = &self.key_state {
            cfg.key_state = (&**key_state).into();
        }

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
        };

        if !self.tags.is_null() {
            let mut tags = vec![];
            // SAFETY: nullity and alignment ensured by safety preconditions
            let mut tag = self.tags;

            while !unsafe { *tag }.is_null() {
                // SAFETY: validity ensured by preconditions, non-nullity by loop condition
                match unsafe { util::str(*tag) } {
                    Some(tag_str) => {
                        tags.push(tag_str.to_owned());
                    }
                    None => {
                        tracing::error!("skipping invalid requested tag");
                    }
                }

                // SAFETY: ensured by preconditions
                tag = unsafe { tag.offset(1) }
            }
        }

        cfg
    }
}

unsafe fn load_sentinel_array<T, It>(
    mut ary: *const T,
    elem_txfm: impl Fn(&T) -> Option<It>,
) -> Vec<It::Item>
where
    It: IntoIterator,
{
    let mut out = vec![];

    if ary.is_null() {
        return out;
    }

    loop {
        // SAFETY: validity ensured by preconditions, non-nullity by loop condition
        match elem_txfm(unsafe { ary.as_ref().unwrap() }) {
            Some(u) => out.extend(u),
            None => {
                break;
            }
        }

        // SAFETY: ensured by preconditions
        ary = unsafe { ary.offset(1) }
    }

    out
}

#[cfg(test)]
mod test {
    use std::{ffi::CString, ptr::null};

    use super::*;

    #[test]
    fn sentinel_array() {
        let v = unsafe { load_sentinel_array::<u8, _>(null(), |_| Option::<[u8; 1]>::None) };
        assert!(v.is_empty());

        let ary = [0u8, 1, 2, 3, 4, 5, 6, 128, 32];

        let v =
            unsafe { load_sentinel_array(&ary as *const u8, |_elt| Option::<Option<u8>>::None) };
        assert!(v.is_empty());

        let v = unsafe {
            load_sentinel_array(
                &ary as *const u8,
                |&elt| {
                    if elt < 10 { Some([elt]) } else { None }
                },
            )
        };
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
