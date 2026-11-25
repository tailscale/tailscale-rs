//! Permissions handling for key state files on Windows.
//!
//! Background: Windows uses an ACL model for permissions whose typical behavior is to
//! inherit file permissions from the parent directory. It calls permissions ACLs DACLs
//! (as opposed to SACLs, which are about auditing -- we don't care about them here). The
//! file owner can alter the ACL, and a number of privileged users and groups can (when
//! appropriately privilege-escalated) gain full control of arbitrary files, roughly similar
//! to root/wheel on unix.
//!
//! Because the parent [`config`][super] module supports creating a file at an arbitrary,
//! user-supplied path, we want to avoid a scenario where `tailscale-rs` key material is
//! accessible to unprivileged users just because it's been placed in a directory with
//! default-public permissions. We need to ensure that the ACL only allows access to the
//! owner of the current process and disables inheritance from the parent directory, as well
//! as ensuring the file owner matches the process owner.
//!
//! To avoid overcomplicating the implementation and guessing what the user might want, the
//! current approach _does not_ respect user-specified ACL entries on the file, it replaces
//! the whole ACL if it doesn't match our desired one. The user should implement their own
//! persistence for [`PersistState`][ts_keys::PersistState] if they need to control this
//! behavior with more granularity.
//!
//! This module provides:
//!
//! - [`check_perms`]: validates that the ACL and owner for the given file are correct
//! - [`fix_perms`]: fixes the perms (ACL + owner) for a given file
//! - [`fix_perms_for_path`]: fixes the perms (ACL + owner) for the file at the given path
//!   (required in some cases because [`fix_perms`] only works if the file was opened in a
//!   specific way)
//! - [`open_for_write`]: open a file with `O_CREAT|O_WRONLY|O_TRUNC` semantics, atomically
//!   setting the ACL while creating it, and fixing the acl/owner (via [`fix_perms`]) if the
//!   file already existed. Use this over [`tokio::fs::File::open`] to set special Windows-
//!   specific capabilities which allow adjusting the DACL.
//!
//! # Administrators
//!
//! The DACL we set also includes an entry which allows members of the `Administrators`
//! group to delete the file. This is to avoid the scenario where an admin wants to delete a
//! whole directory which contains a tailscale-rs key file, and its presence requires them
//! to elevate just to do that. This isn't a security compromise because a) administrators
//! will always be able to take over of the file if they wish, and b) this permission
//! retains the elevation-friction if the admin attempts to read the file (they can still
//! do this, it just shouldn't happen by accident).

use core::{ffi::c_void, ptr::null_mut};
use std::{
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
};

use windows::{
    Win32::{
        Foundation::{
            ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA, GENERIC_WRITE, HANDLE, HLOCAL, LocalFree,
        },
        Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
            Authorization::{
                EXPLICIT_ACCESS_W, GetSecurityInfo, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW,
                SetNamedSecurityInfoW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
                TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
            },
            CopySid, CreateWellKnownSid, DACL_SECURITY_INFORMATION, GetAce, GetLengthSid,
            GetTokenInformation, INHERITED_ACE, IsValidSid, NO_INHERITANCE,
            OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
            SECURITY_DESCRIPTOR_CONTROL, SetSecurityDescriptorControl, TOKEN_QUERY, TOKEN_USER,
            TokenUser, WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid,
        },
        Storage::FileSystem::{
            CREATE_ALWAYS, CreateFileW, DELETE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, WRITE_DAC, WRITE_OWNER,
        },
        System::{
            SystemServices::{ACCESS_ALLOWED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION},
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    },
    core::{PCWSTR, PWSTR},
};

/// A DACL which holds exactly two explicit entries to a) allow full access for the
/// specified principal and b) allow `DELETE` for `Administrators`.
///
/// This is provided as a struct to manage the allocation lifecycle of the contained
/// [`ACL`].
struct OwnerOnlyDacl {
    dacl: *mut ACL,
}

impl OwnerOnlyDacl {
    /// Construct a new dacl for the given owner sid.
    ///
    /// Does not hold a reference to the sid any longer than this function call.
    fn from_owner_sid(owner_sid: PSID) -> windows::core::Result<Self> {
        let mut dacl = null_mut();
        let mut sid_local_admin = OwnedSid::well_known(WinBuiltinAdministratorsSid)?;

        unsafe {
            // SAFETY: no particular safety invariants, just the ffi
            SetEntriesInAclW(
                Some(&[
                    EXPLICIT_ACCESS_W {
                        grfAccessPermissions: FILE_ALL_ACCESS.0,
                        grfInheritance: NO_INHERITANCE,
                        grfAccessMode: SET_ACCESS,

                        Trustee: TRUSTEE_W {
                            TrusteeForm: TRUSTEE_IS_SID,
                            TrusteeType: TRUSTEE_IS_USER,
                            ptstrName: PWSTR(owner_sid.0 as *mut _),

                            ..Default::default()
                        },
                    },
                    EXPLICIT_ACCESS_W {
                        grfAccessPermissions: DELETE.0,
                        grfInheritance: NO_INHERITANCE,
                        grfAccessMode: SET_ACCESS,

                        Trustee: TRUSTEE_W {
                            TrusteeForm: TRUSTEE_IS_SID,
                            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                            // SAFETY: this pointer doesn't outlive the SetEntriesInAclW call.
                            ptstrName: PWSTR(sid_local_admin.as_psid().0 as *mut _),

                            ..Default::default()
                        },
                    },
                ]),
                None,
                &mut dacl,
            )
        }
        .ok()?;

        Ok(Self { dacl })
    }
}

impl Drop for OwnerOnlyDacl {
    fn drop(&mut self) {
        if !self.dacl.is_null() {
            unsafe {
                // SAFETY: checked the argument isn't null, otherwise unsafe is just for ffi.
                LocalFree(Some(HLOCAL(self.dacl as *mut _)));
            }
        }
    }
}

/// Open a file at the given path with `O_WRONLY | O_CREAT | O_TRUNC` semantics, setting the
/// owner and DACL to only allow access from the owner of the current process with no
/// DACL inheritance, as well as allowing administrators to delete it. If the file didn't
/// already exist, these security properties are set atomically with its creation.
///
/// This function technically doesn't play nicely with async, as it doesn't use a polling/
/// async API to interact with Win32 and will therefore block the executor for a bit, which
/// might in principle be able to be avoided. This is done because the `tokio::fs` api
/// doesn't support a clean way to create a file while atomically setting the security
/// descriptor (i.e. so the file can't be observed by another process without the correct
/// DACL and owner). [`tokio::task::block_in_place`] would be the obvious simple solution
/// without having to delve too far into win32 async/callback guts, but this requires a
/// multithreaded executor, which we don't want to assume in general.
///
/// Hence, because we assume this function will only be called at construction-time, which
/// we assume to be rare, we currently accept brief executor blocking here.
pub fn open_for_write(path: impl AsRef<Path>) -> std::io::Result<tokio::fs::File> {
    let mut f = open_file_nocheck(path)?;

    // CreateFileW (invoked by `open_file_nocheck`) does not apply the security descriptor if the
    // file already existed, so we need to check that the DACL is correct and fix it if needed.
    //
    // We generally expect not to hit this case, since with the current code structure in the parent
    // module, it's only hit if the file existed, had correct permissions when we read it the first
    // time, but needed to be updated (e.g. had a format error), then by the time we had opened it
    // for writing, another process or thread raced us and changed the permissions in such a way
    // that the DACL did require an update this second time we saw it. Pretty unlikely, just
    // included for the invariant that this function in all cases makes a best effort to ensure the
    // DACL is correct.
    match check_perms(&f) {
        Ok(_) => {}
        Err(CheckError::Windows(e)) => return Err(e.into()),
        Err(e) => {
            tracing::warn!(error = %e, "bad dacl on key state file, fixing");

            fix_perms(&mut f)?;

            if let Err(e) = check_perms(&f) {
                // TODO(npry): make this a hard error in a future release
                tracing::error!(error = %e, "attempted dacl fix for key state file failed");
            }
        }
    }

    Ok(f)
}

/// The file-opening part of [`open_for_write`] without the permissions checks or
/// attempt to fix them.
///
/// Factored out for tests.
fn open_file_nocheck(path: impl AsRef<Path>) -> std::io::Result<tokio::fs::File> {
    let mut path = path_wide(path.as_ref());
    let path = PCWSTR(path.as_mut_ptr());

    let mut process_owner = process_owner_sid()?;
    // SAFETY: the implied lifetime is that of process_owner_sid, which lives longer than the
    // CreateFileW this dacl is needed for
    let dacl = OwnerOnlyDacl::from_owner_sid(unsafe { process_owner.as_psid() })?;

    let mut sd = SECURITY_DESCRIPTOR {
        Revision: SECURITY_DESCRIPTOR_REVISION as _,
        Control: SECURITY_DESCRIPTOR_CONTROL::default(),
        Dacl: dacl.dacl,
        Group: PSID(null_mut()),
        // SAFETY: the implied lifetime is that of process_owner_sid, which lives longer than the
        // CreateFileW this SECURITY_DESCRIPTOR is needed for
        Owner: unsafe { process_owner.as_psid() },
        Sacl: null_mut(),
        Sbz1: 0,
    };
    let psd = PSECURITY_DESCRIPTOR(&mut sd as *mut _ as *mut _);

    unsafe {
        // SAFETY: psd is non-null
        SetSecurityDescriptorControl(psd, SE_DACL_PROTECTED, SE_DACL_PROTECTED)?;
    }

    let handle = unsafe {
        // SAFETY: path is nul-terminated by `path_wide`; otherwise, no particular safety
        // invariants, just the ffi
        CreateFileW(
            path,
            GENERIC_WRITE.0 | WRITE_DAC.0 | WRITE_OWNER.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            Some(&SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as _,
                lpSecurityDescriptor: &mut sd as *mut _ as *mut _,
                ..Default::default()
            }),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }?;

    // SAFETY: this is an open handle since CreateFileW returned Ok. It's a file so can be closed
    // with CloseHandle.
    let f = unsafe { tokio::fs::File::from_raw_handle(handle.0) };

    Ok(f)
}

// Directly link this rather than pulling in the one through windows-rs because the BOOL -> Result
// conversion has strange behavior (possibly bugged?).
windows::core::link!("advapi32.dll" "system" fn EqualSid(psid1: PSID, psid2: PSID) -> windows::core::BOOL);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CheckError {
    #[error("wrong file owner")]
    WrongOwner,
    #[error("bad dacl size (expected 2 entries)")]
    BadDaclSize,
    #[error("ace has inheritance set")]
    AceInherited,
    #[error("wrong ace type")]
    AceType,
    #[error("dacl had incorrect entry")]
    IncorrectAce,
    #[error(transparent)]
    Windows(#[from] windows::core::Error),
}

/// Check that the DACL and owner on `f` are as we expect: one DACL entry with the
/// current process owner sid which allows all file operations, and one for the local
/// administrators group which allows deletion. The owner should be the current process
/// owner.
pub fn check_perms(f: &tokio::fs::File) -> Result<(), CheckError> {
    let mut owner_psid = process_owner_sid()?;

    let mut actual_owner = PSID::default();
    let mut actual_dacl = <*mut ACL>::default();
    let mut desc = PSECURITY_DESCRIPTOR::default();

    struct DropDesc(PSECURITY_DESCRIPTOR);

    impl Drop for DropDesc {
        fn drop(&mut self) {
            if !self.0.0.is_null() {
                // SAFETY: checked the argument isn't null, otherwise unsafe is just for ffi.
                unsafe { LocalFree(Some(HLOCAL(self.0.0))) };
            }
        }
    }

    unsafe {
        // SAFETY: no particular safety invariants, just the ffi
        GetSecurityInfo(
            HANDLE(f.as_raw_handle()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            Some(&mut actual_owner),
            None,
            Some(&mut actual_dacl),
            None,
            Some(&mut desc),
        )
        .ok()?;
    }

    let _guard = DropDesc(desc);

    // SAFETY: psid just lives for this function call. EqualSid doesn't have safety invariants
    // beyond that it's ffi.
    let correct_owner = unsafe { EqualSid(owner_psid.as_psid(), actual_owner) }.as_bool();
    if !correct_owner {
        return Err(CheckError::WrongOwner);
    }

    // Win32 won't set the DACL-pointer if the DACL is zero length, so ref-convert (which is an
    // implicit null-check) before we check the size field.
    //
    // SAFETY: the pointer is ref-convertible because win32 won't mutate it while we hold it,
    // nothing else sees it, and the lifetime is valid within this function scope (doesn't
    // escape). It's part of the allocation for PSECURITY_DESCRIPTOR, which isn't deallocated until
    // the end of the function, and isn't aliased at or after the time of construction.
    let Some(dacl) = (unsafe { actual_dacl.as_mut() }) else {
        tracing::trace!("empty dacl");
        return Err(CheckError::BadDaclSize);
    };

    if dacl.AceCount != 2 {
        tracing::trace!(dacl_size = dacl.AceCount);
        return Err(CheckError::BadDaclSize);
    }

    // SAFETY: raw psid only lives for this function call
    let idx_user = find_ace(dacl, unsafe { owner_psid.as_psid() }, FILE_ALL_ACCESS.0)?;

    let mut psid_admins = OwnedSid::well_known(WinBuiltinAdministratorsSid)?;
    // SAFETY: raw psid only lives for this function call
    let idx_admin = find_ace(dacl, unsafe { psid_admins.as_psid() }, DELETE.0)?;

    if let Some(idx_user) = idx_user
        && let Some(idx_admin) = idx_admin
        && idx_admin != idx_user
    {
        return Ok(());
    }

    Err(CheckError::IncorrectAce)
}

/// Find the index of an ACE entry in the given DACL that matches the `entry_sid` and
/// `mask`. Note that this just checks if the `mask` bits are all set: it doesn't ensure
/// that additional permissions are _not_ set. Currently, this means that Administrators
/// having given themselves more permissions than DELETE (or the owner having more
/// permissions than `FILE_ALL_ACCESS`) is not treated as an error. Since Administrators
/// can always take over the file anyway, this isn't strictly-speaking an issue.
///
/// The return is an error if calls to Win32 failed or any ACE in the DACL violated
/// invariants (all ACEs are expected to be [`ACCESS_ALLOWED_ACE_TYPE`] and have inheritance
/// disabled).
fn find_ace(dacl: &mut ACL, entry_sid: PSID, mask: u32) -> Result<Option<u32>, CheckError> {
    let mut ace = null_mut();

    for i in 0..dacl.AceCount {
        unsafe {
            // SAFETY: just ffi. The `idx` doesn't need to be valid for safety, windows checks this for
            // us and will error in this case.
            GetAce(dacl, i as _, &mut ace)?;
        }

        {
            let header = ace as *mut ACE_HEADER;
            // SAFETY: cast to ACE_HEADER and deref are valid because GetAce succeeded.
            if unsafe { (*header).AceType } != (ACCESS_ALLOWED_ACE_TYPE as u8) {
                return Err(CheckError::AceType);
            }
        }

        let allowed = ace as *mut ACCESS_ALLOWED_ACE;
        // SAFETY: cast to ACCESS_ALLOWED_ACE and deref are valid because GetAce succeeded and the
        // AceType was ACCESS_ALLOWED_ACE_TYPE.
        if unsafe { (*allowed).Header.AceFlags } & (INHERITED_ACE.0 as u8) != 0 {
            return Err(CheckError::AceInherited);
        }

        // SAFETY: cast to ACCESS_ALLOWED_ACE and deref are valid because GetAce succeeded and the
        // AceType was ACCESS_ALLOWED_ACE_TYPE.
        if unsafe { (*allowed).Mask } & mask != mask {
            continue;
        }

        let actual_sid = unsafe { &mut (*allowed).SidStart } as *mut _ as *mut c_void;
        let actual_sid = PSID(actual_sid);
        // SAFETY: psid just lives for this function call. EqualSid doesn't have safety invariants
        // beyond that it's ffi.
        let correct_sid = unsafe { EqualSid(entry_sid, actual_sid) }.as_bool();
        if !correct_sid {
            continue;
        }

        return Ok(Some(i as _));
    }

    Ok(None)
}

/// Set the DACL for the file at the given path to only have access granted to the owner
/// of the current process, disabling DACL inheritance. Also sets the file owner.
///
/// The file must have been opened with the [`WRITE_DAC`] capability or this will fail. This
/// is separate from [`fix_perms_for_path`] because on the one hand it operates on an open
/// file handle, but has this constraint about [`WRITE_DAC`] ([`fix_perms_for_path`]
/// acquires this automatically because it isn't constrained to the existing handle).
pub fn fix_perms(f: &mut tokio::fs::File) -> std::io::Result<()> {
    let mut owner_psid = process_owner_sid()?;
    let dacl = OwnerOnlyDacl::from_owner_sid(unsafe { owner_psid.as_psid() })?;

    tracing::trace!("updating perms by handle");
    unsafe {
        // SAFETY: no particular safety invariants, just the ffi
        SetSecurityInfo(
            HANDLE(f.as_raw_handle()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION
                | OWNER_SECURITY_INFORMATION,
            // SAFETY: PSID is lifetime-constrained to just this function call
            Some(owner_psid.as_psid()),
            None,
            Some(dacl.dacl),
            None,
        )
        .ok()?;
    }

    Ok(())
}

/// Set the DACL for the file at the given path to only have access granted to the owner
/// of the current process, disabling DACL inheritance. Also sets the file owner.
///
/// This is separate from [`fix_perms`] because it operates on a path rather than an open
/// handle. This allows it to automatically acquire [`WRITE_DAC`].
pub fn fix_perms_for_path(path: impl AsRef<Path>) -> std::io::Result<()> {
    let path = path_wide(path.as_ref());
    let path = PCWSTR(path.as_ptr());

    let mut owner_psid = process_owner_sid()?;
    // SAFETY: PSID is lifetime-constrained to just this function call
    let dacl = OwnerOnlyDacl::from_owner_sid(unsafe { owner_psid.as_psid() })?;

    tracing::trace!("updating perms by path");
    unsafe {
        // SAFETY: no particular safety invariants, just the ffi
        SetNamedSecurityInfoW(
            path,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION
                | OWNER_SECURITY_INFORMATION,
            // SAFETY: the PSID only lives for this function call
            Some(owner_psid.as_psid()),
            None,
            Some(dacl.dacl),
            None,
        )
        .ok()?;
    }

    Ok(())
}

/// A SID which owns and manages the allocation of its backing storage.
///
/// Convertible to/from the [`PSID`] that most of the win32 security APIs expect.
struct OwnedSid(Vec<u8>);

impl OwnedSid {
    fn copy_from(psid: PSID) -> windows::core::Result<Self> {
        // SAFETY: checked if null (this is all the API requires).
        if psid.is_invalid() || !unsafe { IsValidSid(psid).as_bool() } {
            return Err(ERROR_INVALID_DATA.into());
        }

        // SAFETY: checked that the sid is valid.
        let len = unsafe { GetLengthSid(psid) };
        let mut out = vec![0u8; len as usize];

        // SAFETY: length is specified as the length in bytes for both getlengthsid and copysid.
        unsafe { CopySid(len, PSID(out.as_mut_ptr() as *mut _), psid) }?;

        Ok(Self(out))
    }

    /// Construct a well-known sid of the given type.
    ///
    /// Assumes no domain component.
    fn well_known(ty: WELL_KNOWN_SID_TYPE) -> windows::core::Result<Self> {
        let mut len = 32u32;
        let mut out = vec![0u8; len as usize];

        unsafe { CreateWellKnownSid(ty, None, Some(PSID(out.as_mut_ptr() as *mut _)), &mut len) }?;

        // CreateWellKnownSid mutates len to indicate how many bytes it actually took up.
        out.truncate(len as usize);

        Ok(Self(out))
    }

    /// Convert this into a [`PSID`].
    ///
    /// # Safety
    ///
    /// You must guarantee that the returned [`PSID`] doesn't outlive this [`OwnedSid`].
    unsafe fn as_psid(&mut self) -> PSID {
        PSID(self.0.as_mut_ptr() as *mut _)
    }
}

/// Get the sid of the owner of the current process.
fn process_owner_sid() -> windows::core::Result<OwnedSid> {
    unsafe {
        let mut token_handle = HANDLE::default();
        // SAFETY: no specific safety invariants, just ffi.
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle)?;

        let mut len = 0;

        // This is expected to return ERROR_INSUFFICIENT_BUFFER (it will populate `len` anyway).
        // SAFETY: no specific safety invariants, just ffi.
        match GetTokenInformation(token_handle, TokenUser, None, 0, &mut len) {
            Ok(()) => {}
            Err(e) if e.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => {}
            Err(e) => return Err(e),
        }

        let mut buf = vec![0u8; len as usize];

        // SAFETY: no specific safety invariants, just ffi.
        GetTokenInformation(
            token_handle,
            TokenUser,
            Some(buf.as_mut_ptr() as _),
            len,
            &mut len,
        )?;

        // SAFETY: Win32 told us it got the token successfully in the last call, and we requested
        // TokenUser, so the buffer can be interpreted as a TOKEN_USER.
        let ret = (*(buf.as_mut_ptr() as *mut TOKEN_USER)).User.Sid;
        if ret.is_invalid() {
            return Err(ERROR_INVALID_DATA.into());
        }

        OwnedSid::copy_from(ret)
    }
}

fn path_wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain([0]).collect()
}

#[cfg(test)]
mod test {
    use windows::Win32::{
        Foundation::GENERIC_READ,
        Security::{Authorization::TRUSTEE_TYPE, UNPROTECTED_DACL_SECURITY_INFORMATION},
    };

    use super::*;

    #[test]
    fn process_sid() {
        process_owner_sid().unwrap();
    }

    #[tracing_test::traced_test]
    #[test]
    fn set_dacl_basic() -> std::io::Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;

        let mut f = open_file_nocheck(tmp.path())?;
        assert!(check_perms(&f).is_err());

        fix_perms(&mut f)?;
        check_perms(&f).unwrap();

        Ok(())
    }

    #[tracing_test::traced_test]
    #[test]
    fn open_for_write_new() -> std::io::Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;
        let path = tmp.path().to_path_buf();

        // delete the temp file so we can recreate it -- just using `tempfile` to manage creating
        // a directory
        tmp.close()?;

        let f = open_for_write(path)?;
        check_perms(&f).unwrap();

        Ok(())
    }

    #[tracing_test::traced_test]
    #[test]
    fn open_for_write_existing() -> std::io::Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;

        {
            let f = open_for_write(tmp.path())?;
            clear_dacl(&f)?;

            let result = check_perms(&f);
            assert!(matches!(result, Err(CheckError::BadDaclSize)));
        }

        let f = open_for_write(tmp.path())?;
        check_perms(&f).unwrap();

        Ok(())
    }

    fn clear_dacl(f: &tokio::fs::File) -> std::io::Result<()> {
        let mut null_dacl = null_mut();

        unsafe {
            // SAFETY: no particular safety invariants, just the ffi
            SetEntriesInAclW(Some(&[]), None, &mut null_dacl).ok()?;

            // SAFETY: no particular safety invariants, just the ffi
            SetSecurityInfo(
                HANDLE(f.as_raw_handle()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(null_dacl),
                None,
            )
            .ok()?;
        }

        Ok(())
    }

    fn admin_good() -> std::io::Result<(OwnedSid, TRUSTEE_TYPE, u32)> {
        let sid = OwnedSid::well_known(WinBuiltinAdministratorsSid)?;

        Ok((sid, TRUSTEE_IS_WELL_KNOWN_GROUP, DELETE.0))
    }

    fn user_good() -> std::io::Result<(OwnedSid, TRUSTEE_TYPE, u32)> {
        let sid = process_owner_sid()?;

        Ok((sid, TRUSTEE_IS_USER, FILE_ALL_ACCESS.0))
    }

    #[test]
    fn check_missing_admin() -> std::io::Result<()> {
        let (mut sid, ty, perms) = user_good()?;

        // SAFETY: sid just held for this call
        assert_check_error(
            [CheckError::BadDaclSize],
            [(unsafe { sid.as_psid() }, ty, perms)],
            false,
        )
    }

    #[test]
    fn check_missing_user() -> std::io::Result<()> {
        let (mut sid, ty, perms) = admin_good()?;

        // SAFETY: sid just held for this call
        assert_check_error(
            [CheckError::BadDaclSize],
            [(unsafe { sid.as_psid() }, ty, perms)],
            false,
        )
    }

    #[test]
    fn check_wrong_user_perms() -> std::io::Result<()> {
        let (mut user_sid, user_ty, user_perms) = user_good()?;
        let (mut admin_sid, admin_ty, _) = admin_good()?;

        assert_check_error(
            [CheckError::IncorrectAce],
            [
                // SAFETY: sid just held for this call
                (unsafe { user_sid.as_psid() }, user_ty, user_perms),
                // SAFETY: sid just held for this call
                (unsafe { admin_sid.as_psid() }, admin_ty, GENERIC_READ.0),
            ],
            false,
        )
    }

    #[test]
    fn check_wrong_admin_perms() -> std::io::Result<()> {
        let (mut user_sid, user_ty, _) = user_good()?;
        let (mut admin_sid, admin_ty, admin_perms) = admin_good()?;

        assert_check_error(
            [CheckError::IncorrectAce],
            [
                // SAFETY: sid just held for this call
                (unsafe { user_sid.as_psid() }, user_ty, GENERIC_READ.0),
                // SAFETY: sid just held for this call
                (unsafe { admin_sid.as_psid() }, admin_ty, admin_perms),
            ],
            false,
        )
    }

    #[tracing_test::traced_test]
    #[test]
    fn check_inheritance() -> std::io::Result<()> {
        let (mut user_sid, user_ty, user_perms) = user_good()?;
        let (mut admin_sid, admin_ty, admin_perms) = admin_good()?;

        assert_check_error(
            // We don't control the inherited dacl size, so it's actually more likely we get bad
            // size here.
            [CheckError::AceInherited, CheckError::BadDaclSize],
            [
                // SAFETY: sid just held for this call
                (unsafe { user_sid.as_psid() }, user_ty, user_perms),
                // SAFETY: sid just held for this call
                (unsafe { admin_sid.as_psid() }, admin_ty, admin_perms),
            ],
            true,
        )?;

        Ok(())
    }

    #[test]
    fn check_empty_dacl() -> std::io::Result<()> {
        assert_check_error([CheckError::BadDaclSize], [], false)
    }

    fn assert_check_error(
        permitted_errors: impl IntoIterator<Item = CheckError>,
        dacl: impl IntoIterator<Item = (PSID, TRUSTEE_TYPE, u32)>,
        inherit: bool,
    ) -> std::io::Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;
        let mut f = open_for_write(tmp.path())?;

        set_dacl(&mut f, dacl, inherit)?;

        let result = check_perms(&f).unwrap_err();
        assert!(permitted_errors.into_iter().any(|e| result == e));

        Ok(())
    }

    fn set_dacl(
        f: &mut tokio::fs::File,
        entries: impl IntoIterator<Item = (PSID, TRUSTEE_TYPE, u32)>,
        inherit: bool,
    ) -> std::io::Result<()> {
        let mut dacl = null_mut();

        let entries = entries
            .into_iter()
            .map(|(sid, ty, perms)| EXPLICIT_ACCESS_W {
                grfAccessPermissions: perms,
                grfInheritance: NO_INHERITANCE,
                grfAccessMode: SET_ACCESS,

                Trustee: TRUSTEE_W {
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: ty,
                    ptstrName: PWSTR(sid.0 as *mut _),

                    ..Default::default()
                },
            })
            .collect::<Vec<_>>();

        let mut info = DACL_SECURITY_INFORMATION;
        if inherit {
            info |= UNPROTECTED_DACL_SECURITY_INFORMATION;
        } else {
            info |= PROTECTED_DACL_SECURITY_INFORMATION;
        }

        unsafe {
            // SAFETY: no particular safety invariants, just the ffi
            SetEntriesInAclW(Some(&entries), None, &mut dacl).ok()?;

            // SAFETY: no particular safety invariants, just the ffi
            let result = SetSecurityInfo(
                HANDLE(f.as_raw_handle()),
                SE_FILE_OBJECT,
                info,
                None,
                None,
                Some(dacl),
                None,
            );

            if !dacl.is_null() {
                // SAFETY: null-checked, otherwise just ffi
                LocalFree(Some(HLOCAL(dacl as _)));
            }

            result.ok()?;
        }

        Ok(())
    }

    // TODO(npry): ci test environment which allows running as elevated. We can't check the
    //  owner validation without assigning another owner to the file, which generically we
    //  can only do if we create one (for hermeticity this would require one per test, which
    //  seems likely to be painful), or by assigning a builtin group like Administrators.
    //  But you can only do that if you're elevated, so for now these #[ignore]d tests only
    //  run on developer machines. If you have Windows 11 `sudo`, you can run them with
    //  `sudo cargo run -- --ignored config::windows`, or otherwise using an elevated
    //  command prompt.

    #[tracing_test::traced_test]
    #[test]
    #[ignore = "requires elevation to change file owner"]
    fn check_wrong_owner() -> std::io::Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;

        let f = open_for_write(tmp.path())?;
        set_bad_owner(&f)?;

        let result = check_perms(&f);
        assert!(matches!(result, Err(CheckError::WrongOwner)));

        Ok(())
    }

    #[tracing_test::traced_test]
    #[test]
    #[ignore = "requires elevation to change file owner"]
    fn fix_owner() -> std::io::Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;

        {
            let f = open_for_write(tmp.path())?;
            set_bad_owner(&f)?;
        }

        let f = open_for_write(tmp.path())?;
        check_perms(&f).unwrap();

        Ok(())
    }

    fn set_bad_owner(f: &tokio::fs::File) -> std::io::Result<()> {
        let mut admin_sid = OwnedSid::well_known(WinBuiltinAdministratorsSid)?;

        unsafe {
            // SAFETY: no particular safety invariants, just the ffi
            SetSecurityInfo(
                HANDLE(f.as_raw_handle()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                // SAFETY: just lives for this call
                Some(admin_sid.as_psid()),
                None,
                None,
                None,
            )
            .ok()?;
        }

        Ok(())
    }
}
