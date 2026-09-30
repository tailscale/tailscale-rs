use serde::{Deserialize, Serialize};

/// Contains information about a TPM 2.0 device present on a Tailscale node. All fields are read
/// from the TPM device's `TPM_CAP_TPM_PROPERTIES` capability.
///
/// See: Part 2, Section 6.13 of the
/// [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TpmInfo<'a> {
    /// A 4-letter code representing the manufacturer of the TPM device; for example, "MSFT" for
    /// Microsoft. Read from the TPM device's `TPM_PT_MANUFACTURER` property tag.
    ///
    /// See: Section 4.1 of the
    /// [TPM Vendor ID registry](https://trustedcomputinggroup.org/resource/vendor-id-registry/).
    pub manufacturer: [char; 4],
    /// A free-form vendor ID string, up to 16 characters. Read from the four
    /// `TPM_PT_VENDOR_STRING_{1-4}` property tags on the TPM device; each property tag contains
    /// 4 of the 16 possible characters.
    ///
    /// See: Part 2, Section 6.13 of the
    /// [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/).
    #[serde(borrow)]
    pub vendor: &'a str,
    /// A free-form, vendor-defined TPM model. Read from the TPM device's `TPM_PT_VENDOR_TPM_TYPE`
    /// property tag.
    ///
    /// See: Part 2, Section 6.13 of the
    /// [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/).
    #[serde(borrow)]
    pub model: &'a str,
    /// A free-form, vendor-defined version number for the TPM firmware. Read from the two
    /// `TPM_PT_FIRMWARE_VERSION_{1,2}` property tags on the TPM device, and represented as a
    /// single string.
    ///
    /// See: Part 2, Section 6.13 of the
    /// [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/).
    ///
    /// For info on this value and time attestation, see Part 2, Section 10.12.2 of the
    /// [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/).
    ///
    /// For info on this value and general data attestation, see Part 2, Section 10.12.12 of the
    /// [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/).
    #[serde(borrow)]
    pub firmware_version: &'a str,
    /// The TPM 2.0 spec revision encoded as a single number. Before revision 184, TCG used the
    /// "01.83" format for revision 183; as of revision 184 and later, the revision is represented
    /// as an unsigned integer, e.g. `184`.
    ///
    /// All revisions can be found at <https://trustedcomputinggroup.org/resource/tpm-library-specification/>.
    /// For a discussion of how `TPM_SPEC_VERSION` has changed, see: Part 2, Section 6.1 of the
    /// [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/).
    #[serde(skip_serializing_if = "crate::util::is_default")]
    pub spec_revision: usize,
}
