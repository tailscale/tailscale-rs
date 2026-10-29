//! Unix-specific permissions checking.
//!
//! # POSIX ACLs
//!
//! POSIX ACLs treat the owner user separately from other user entries in the ACL. The owner
//! always receives access rights from the user bits of the file mode, while any other user
//! in the ACL has any rights provided by ACL entries masked by the group mode bits (they
//! describe an upper bound on non-owner permissions). Since we set a mode of `0600`, access
//! rights are masked out for all users other than the owner, regardless of what ACL is set.
//! This is desired behavior.

use std::os::unix::fs::PermissionsExt;

/// Check perms on the given file, emitting a warning (and returning `false`) if not `0600`.
pub async fn check_perms(f: &mut tokio::fs::File) -> std::io::Result<bool> {
    let meta = f.metadata().await?;
    let mode = meta.permissions().mode() & 0o777;

    if mode == 0o600 {
        return Ok(true);
    }

    Ok(false)
}

/// Set the permissions on `f` to `0600`.
pub async fn fix_perms(f: &mut tokio::fs::File) -> std::io::Result<()> {
    let mut perms = f.metadata().await?.permissions();
    perms.set_mode(0o600);

    f.set_permissions(perms).await?;
    tracing::debug!("set key file permissions to 0600");

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::try_write;

    #[tokio::test]
    async fn verify_perms() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::NamedTempFile::new().unwrap();

        let path = tmp.path().to_path_buf();
        let mut f = tokio::fs::File::from_std(tmp.into_file());

        try_write(&path, &"abc").await.unwrap();
        assert!(check_perms(&mut f).await.unwrap());

        let mut perms = f.metadata().await.unwrap().permissions();
        perms.set_mode(0o664);
        f.set_permissions(perms).await.unwrap();

        assert!(!check_perms(&mut f).await.unwrap());
    }
}
