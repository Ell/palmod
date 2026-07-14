//! Build fingerprints and compatibility profiles for the native Palworld loader.
//!
//! Profiles deliberately contain no game binaries or generated SDK data. They bind a
//! small set of reviewed RVAs and reflection facts to one exact ELF fingerprint.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use object::{Object, ObjectSegment, SegmentFlags};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROFILE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse TOML profile: {0}")]
    ParseToml(#[from] toml::de::Error),
    #[error("failed to serialize TOML profile: {0}")]
    SerializeToml(#[from] toml::ser::Error),
    #[error("invalid profile: {0}")]
    Validation(String),
    #[error("invalid ELF: {0}")]
    Elf(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildProfile {
    pub schema: u32,
    pub status: ProfileStatus,
    pub profile_id: String,
    pub steam_build_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depot_manifest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub palworld_version: Option<String>,
    pub elf: ElfFingerprint,
    #[serde(default)]
    pub anchors: BTreeMap<String, Anchor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reflection: Option<ReflectionProfile>,
}

/// Dynamically observed Unreal reflection layout for this exact build. Used by
/// the in-process reflection hook backend to locate `UFunction::Func` slots by
/// scanning for a known exec-thunk pointer and confirming the vtable at
/// `slot - ufunction_func_offset`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReflectionProfile {
    /// Offset of `UFunction::Func` within a `UFunction` object.
    pub ufunction_func_offset: u64,
    /// Virtual address of the shared `UFunction` class vtable.
    pub ufunction_vtable_va: u64,
    /// Offset of `Locals` (the `Parms` buffer) within an exec-thunk `FFrame` — a
    /// per-build constant shared by every function, used by generic by-name hooks
    /// to reach the arguments. Absent means the runtime default (`0x18`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fframe_locals_offset: Option<u64>,
    /// VA of `FNamePool.Blocks`. Lets generic hooks resolve `NameProperty`
    /// arguments to strings instead of raw indices. Absent means no resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fname_pool_blocks_va: Option<u64>,
    /// `UObject::ProcessEvent` vtable slot — the build-wide dispatch entry used to
    /// call any `UFunction` generically. Absent means no generic call path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_event_vtable_slot: Option<u64>,
    /// VA of `GUObjectArray.ObjObjects.Objects` — the object-array walker uses it
    /// to find objects/functions by name (target `this`, generic dispatch).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guobjectarray_objects_va: Option<u64>,
    /// `UStruct::SuperStruct` offset, for the `IsA` class-chain check while walking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub super_struct_offset: Option<u64>,
    /// Facts for the chat interception hook (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat: Option<ChatHookFacts>,
    /// Facts for the game-thread drain pump (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_tick: Option<EngineTickFacts>,
    /// Facts for the server-side admin check (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<AdminFacts>,
}

/// Server-side admin check facts: honor Palworld's own admin login by reading
/// `PalPlayerController.bAdmin`, correlating the chat `SenderPlayerUId` (Guid) to
/// the player's `PalPlayerState.PlayerUId`. All reflection-derived + live-validated
/// (`bAdmin` flips to 1 on in-game `AdminPassword` login).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminFacts {
    pub controller_class: String,
    pub player_state_offset: u64,
    pub player_uid_offset: u64,
    pub badmin_offset: u64,
    pub sender_player_uid_offset: u64,
}

/// Build-specific facts for the game-thread drain: swapping `GEngine`'s `Tick`
/// vtable entry drains the action queue once per frame on the game thread (the
/// data-pointer-swap equivalent of UE4SS's `EngineTick` method). `gengine_global_va`
/// is the address of the `GEngine` pointer variable; `tick_vtable_slot` is the
/// `UEngine::Tick` slot index.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineTickFacts {
    pub gengine_global_va: u64,
    pub tick_vtable_slot: u64,
}

/// Build-specific facts to install the reflection chat hook: which `UFunction` to
/// swap and how to decode its `FPalChatMessage`. Recovered from the reflection
/// dump and confirmed live.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatHookFacts {
    /// RVA of `BroadcastChatMessage`'s exec thunk (its `UFunction::Func` value).
    pub broadcast_thunk_rva: u64,
    /// Offset of `Locals` (the `Parms` buffer) within the exec-thunk `FFrame`.
    pub fframe_locals_offset: u64,
    /// Offsets of the sender/message `FString`s within `FPalChatMessage`.
    pub message_sender_offset: u64,
    pub message_text_offset: u64,
}

impl ReflectionProfile {
    fn validate(&self) -> Result<(), ProfileError> {
        if self.ufunction_func_offset == 0 || self.ufunction_func_offset > 0x1000 {
            return Err(ProfileError::Validation(
                "reflection: ufunction_func_offset is out of the expected range".to_owned(),
            ));
        }
        if self.ufunction_vtable_va == 0 {
            return Err(ProfileError::Validation(
                "reflection: ufunction_vtable_va must be non-zero".to_owned(),
            ));
        }
        if let Some(offset) = self.fframe_locals_offset
            && (offset == 0 || offset > 0x1000)
        {
            return Err(ProfileError::Validation(
                "reflection: fframe_locals_offset is out of the expected range".to_owned(),
            ));
        }
        if self.fname_pool_blocks_va == Some(0) {
            return Err(ProfileError::Validation(
                "reflection: fname_pool_blocks_va must be non-zero when present".to_owned(),
            ));
        }
        if self.guobjectarray_objects_va == Some(0) {
            return Err(ProfileError::Validation(
                "reflection: guobjectarray_objects_va must be non-zero when present".to_owned(),
            ));
        }
        if let Some(tick) = &self.engine_tick
            && (tick.gengine_global_va == 0 || tick.tick_vtable_slot > 0x1000)
        {
            return Err(ProfileError::Validation(
                "reflection.engine_tick: gengine_global_va must be nonzero and \
                 tick_vtable_slot small"
                    .to_owned(),
            ));
        }
        if let Some(admin) = &self.admin
            && (admin.controller_class.is_empty() || admin.badmin_offset == 0)
        {
            return Err(ProfileError::Validation(
                "reflection.admin requires a controller_class + nonzero badmin_offset".to_owned(),
            ));
        }
        if let Some(chat) = &self.chat {
            if chat.broadcast_thunk_rva == 0 {
                return Err(ProfileError::Validation(
                    "reflection.chat: broadcast_thunk_rva must be non-zero".to_owned(),
                ));
            }
            if chat.fframe_locals_offset > 0x1000 || chat.message_text_offset > 0x1000 {
                return Err(ProfileError::Validation(
                    "reflection.chat: offsets are out of the expected range".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

impl BuildProfile {
    #[must_use]
    pub fn candidate(steam_build_id: impl Into<String>, elf: ElfFingerprint) -> Self {
        let steam_build_id = steam_build_id.into();
        let digest_prefix = elf.sha256.get(..16).unwrap_or(&elf.sha256);
        Self {
            schema: PROFILE_SCHEMA_VERSION,
            status: ProfileStatus::Candidate,
            profile_id: format!("palworld-linux-{steam_build_id}-{digest_prefix}"),
            steam_build_id,
            depot_manifest: None,
            palworld_version: None,
            elf,
            anchors: BTreeMap::new(),
            reflection: None,
        }
    }

    pub fn from_toml(input: &str) -> Result<Self, ProfileError> {
        let profile: Self = toml::from_str(input)?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn read_toml(path: impl AsRef<Path>) -> Result<Self, ProfileError> {
        let path = path.as_ref();
        let input = fs::read_to_string(path).map_err(|source| ProfileError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_toml(&input)
    }

    pub fn to_toml_pretty(&self) -> Result<String, ProfileError> {
        self.validate()?;
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.schema != PROFILE_SCHEMA_VERSION {
            return Err(ProfileError::Validation(format!(
                "unsupported schema {}; expected {PROFILE_SCHEMA_VERSION}",
                self.schema
            )));
        }
        validate_symbolic_name("profile", &self.profile_id)?;
        validate_decimal_identifier("steam_build_id", &self.steam_build_id)?;
        if let Some(manifest) = &self.depot_manifest {
            validate_decimal_identifier("depot_manifest", manifest)?;
        }
        self.elf.validate()?;

        for (name, anchor) in &self.anchors {
            validate_symbolic_name("anchor", name)?;
            anchor.validate(name)?;
        }
        if self.status == ProfileStatus::Validated && self.anchors.is_empty() {
            return Err(ProfileError::Validation(
                "validated profile must contain at least one anchor".to_owned(),
            ));
        }
        if let Some(reflection) = &self.reflection {
            reflection.validate()?;
        }
        Ok(())
    }

    /// Deterministic JSON form passed from the launcher to the native loader.
    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, ProfileError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| ProfileError::Validation(format!("canonical encoding: {error}")))
    }

    #[must_use]
    pub fn matches_fingerprint(&self, actual: &ElfFingerprint) -> bool {
        self.elf == *actual
    }

    /// Verify masked expected bytes and offline validators against the exact ELF.
    pub fn verify_anchor_bytes(&self, path: impl AsRef<Path>) -> Result<(), ProfileError> {
        let bytes = read(path.as_ref())?;
        let file = object::File::parse(bytes.as_slice())
            .map_err(|error| ProfileError::Elf(error.to_string()))?;
        for (name, anchor) in &self.anchors {
            let address =
                self.elf.image_base.checked_add(anchor.rva).ok_or_else(|| {
                    ProfileError::Validation(format!("anchor {name}: RVA overflow"))
                })?;
            let (segment_data, offset, executable) =
                locate_segment(&file, address).ok_or_else(|| {
                    ProfileError::Validation(format!(
                        "anchor {name}: address {address:#x} is outside loadable segments"
                    ))
                })?;
            if !anchor.expected_bytes.matches_at(segment_data, offset) {
                return Err(ProfileError::Validation(format!(
                    "anchor {name}: expected bytes do not match at {address:#x}"
                )));
            }
            if anchor.validators.contains(&AnchorValidator::Executable) && !executable {
                return Err(ProfileError::Validation(format!(
                    "anchor {name}: target segment is not executable"
                )));
            }
            if anchor.validators.contains(&AnchorValidator::Unique) {
                let matches = file
                    .segments()
                    .filter_map(|segment| segment.data().ok())
                    .map(|data| anchor.expected_bytes.count_matches(data))
                    .sum::<usize>();
                if matches != 1 {
                    return Err(ProfileError::Validation(format!(
                        "anchor {name}: expected unique pattern, found {matches} matches"
                    )));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileStatus {
    Candidate,
    Validated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfFingerprint {
    pub sha256: String,
    pub build_id: String,
    pub machine: String,
    pub bits: u8,
    pub endian: String,
    pub elf_type: String,
    pub image_base: u64,
    pub file_size: u64,
}

impl ElfFingerprint {
    fn validate(&self) -> Result<(), ProfileError> {
        validate_hex("elf.sha256", &self.sha256, Some(32))?;
        validate_hex("elf.build_id", &self.build_id, None)?;
        if self.machine != "x86_64" {
            return Err(ProfileError::Validation(format!(
                "unsupported machine {}; only x86_64 is supported",
                self.machine
            )));
        }
        if self.bits != 64 || self.endian != "little" {
            return Err(ProfileError::Validation(
                "only little-endian 64-bit ELF is supported".to_owned(),
            ));
        }
        if !matches!(self.elf_type.as_str(), "ET_EXEC" | "ET_DYN") {
            return Err(ProfileError::Validation(format!(
                "unsupported ELF type {}",
                self.elf_type
            )));
        }
        if self.file_size == 0 {
            return Err(ProfileError::Validation(
                "elf.file_size must be non-zero".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub rva: u64,
    pub expected_bytes: BytePattern,
    #[serde(default)]
    pub validators: BTreeSet<AnchorValidator>,
}

impl Anchor {
    fn validate(&self, name: &str) -> Result<(), ProfileError> {
        if self.expected_bytes.is_empty() {
            return Err(ProfileError::Validation(format!(
                "anchor {name}: expected_bytes cannot be empty"
            )));
        }
        if self.expected_bytes.len() > 256 {
            return Err(ProfileError::Validation(format!(
                "anchor {name}: expected_bytes exceeds 256 bytes"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnchorValidator {
    Executable,
    Unique,
    ReflectionSmoke,
}

/// A masked byte pattern serialized as space-separated hex (`48 8b ?? 90`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BytePattern(Vec<Option<u8>>);

impl BytePattern {
    pub fn parse(input: &str) -> Result<Self, ProfileError> {
        let mut bytes = Vec::new();
        for token in input.split_whitespace() {
            if token == "??" || token == "?" {
                bytes.push(None);
                continue;
            }
            if token.len() != 2 {
                return Err(ProfileError::Validation(format!(
                    "invalid expected byte token {token:?}"
                )));
            }
            let byte = u8::from_str_radix(token, 16).map_err(|_| {
                ProfileError::Validation(format!("invalid expected byte token {token:?}"))
            })?;
            bytes.push(Some(byte));
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn matches(&self, input: &[u8]) -> bool {
        input.len() >= self.len()
            && self
                .0
                .iter()
                .zip(input)
                .all(|(expected, actual)| expected.is_none_or(|byte| byte == *actual))
    }

    #[must_use]
    pub fn matches_at(&self, input: &[u8], offset: usize) -> bool {
        input.get(offset..).is_some_and(|tail| self.matches(tail))
    }

    #[must_use]
    pub fn count_matches(&self, input: &[u8]) -> usize {
        if self.is_empty() || input.len() < self.len() {
            return 0;
        }
        input
            .windows(self.len())
            .filter(|window| self.matches(window))
            .count()
    }
}

impl fmt::Display for BytePattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index > 0 {
                formatter.write_str(" ")?;
            }
            match byte {
                Some(byte) => write!(formatter, "{byte:02x}")?,
                None => formatter.write_str("??")?,
            }
        }
        Ok(())
    }
}

impl Serialize for BytePattern {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for BytePattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = String::deserialize(deserializer)?;
        Self::parse(&input).map_err(serde::de::Error::custom)
    }
}

pub fn fingerprint_path(path: impl AsRef<Path>) -> Result<ElfFingerprint, ProfileError> {
    let bytes = read(path.as_ref())?;
    fingerprint_bytes(&bytes)
}

pub fn fingerprint_bytes(bytes: &[u8]) -> Result<ElfFingerprint, ProfileError> {
    if bytes.len() < 20 || &bytes[..4] != b"\x7fELF" {
        return Err(ProfileError::Elf("not an ELF file".to_owned()));
    }
    let (bits, class) = match bytes[4] {
        2 => (64, 2),
        1 => (32, 1),
        value => return Err(ProfileError::Elf(format!("unknown ELF class {value}"))),
    };
    let (endian, little) = match bytes[5] {
        1 => ("little", true),
        2 => ("big", false),
        value => return Err(ProfileError::Elf(format!("unknown ELF endian {value}"))),
    };
    let read_u16 = |offset: usize| {
        let bytes = [bytes[offset], bytes[offset + 1]];
        if little {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        }
    };
    let elf_type = match read_u16(16) {
        2 => "ET_EXEC",
        3 => "ET_DYN",
        value => return Err(ProfileError::Elf(format!("unsupported ELF type {value}"))),
    };
    let machine = match read_u16(18) {
        62 => "x86_64",
        183 => "aarch64",
        value => {
            return Err(ProfileError::Elf(format!(
                "unsupported ELF machine {value}"
            )));
        }
    };
    let file = object::File::parse(bytes).map_err(|error| ProfileError::Elf(error.to_string()))?;
    let build_id = file
        .build_id()
        .map_err(|error| ProfileError::Elf(format!("GNU build ID: {error}")))?
        .ok_or_else(|| ProfileError::Elf("GNU build ID is missing".to_owned()))?;
    let image_base = file
        .segments()
        .filter(|segment| segment.size() > 0)
        .map(|segment| segment.address())
        .min()
        .ok_or_else(|| ProfileError::Elf("ELF has no loadable segments".to_owned()))?;

    let fingerprint = ElfFingerprint {
        sha256: hex::encode(Sha256::digest(bytes)),
        build_id: hex::encode(build_id),
        machine: machine.to_owned(),
        bits: if class == 2 { bits } else { 32 },
        endian: endian.to_owned(),
        elf_type: elf_type.to_owned(),
        image_base,
        file_size: u64::try_from(bytes.len())
            .map_err(|_| ProfileError::Elf("ELF size does not fit u64".to_owned()))?,
    };
    fingerprint.validate()?;
    Ok(fingerprint)
}

fn read(path: &Path) -> Result<Vec<u8>, ProfileError> {
    fs::read(path).map_err(|source| ProfileError::Read {
        path: path.display().to_string(),
        source,
    })
}

fn locate_segment<'a>(file: &'a object::File<'a>, address: u64) -> Option<(&'a [u8], usize, bool)> {
    file.segments().find_map(|segment| {
        let start = segment.address();
        let relative = address.checked_sub(start)?;
        if relative >= segment.size() {
            return None;
        }
        let offset = usize::try_from(relative).ok()?;
        let data = segment.data().ok()?;
        let executable =
            matches!(segment.flags(), SegmentFlags::Elf { p_flags } if p_flags & 1 != 0);
        Some((data, offset, executable))
    })
}

fn validate_decimal_identifier(field: &str, value: &str) -> Result<(), ProfileError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ProfileError::Validation(format!(
            "{field} must contain decimal digits"
        )));
    }
    Ok(())
}

fn validate_symbolic_name(kind: &str, name: &str) -> Result<(), ProfileError> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(ProfileError::Validation(format!(
            "invalid {kind} name {name:?}"
        )));
    }
    Ok(())
}

fn validate_hex(
    field: &str,
    value: &str,
    expected_bytes: Option<usize>,
) -> Result<(), ProfileError> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ProfileError::Validation(format!(
            "{field} must be non-empty, even-length hexadecimal"
        )));
    }
    if let Some(expected) = expected_bytes
        && value.len() != expected * 2
    {
        return Err(ProfileError::Validation(format!(
            "{field} must contain exactly {expected} bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> BuildProfile {
        let mut profile = BuildProfile::candidate(
            "24088465",
            ElfFingerprint {
                sha256: "aa".repeat(32),
                build_id: "bb".repeat(20),
                machine: "x86_64".to_owned(),
                bits: 64,
                endian: "little".to_owned(),
                elf_type: "ET_EXEC".to_owned(),
                image_base: 0x20_0000,
                file_size: 1024,
            },
        );
        profile.anchors.insert(
            "process_event".to_owned(),
            Anchor {
                rva: 0x1234,
                expected_bytes: BytePattern::parse("48 8b ?? 90").unwrap(),
                validators: [AnchorValidator::Executable].into_iter().collect(),
            },
        );
        profile
    }

    #[test]
    fn reflection_profile_validates_and_round_trips() {
        let mut profile = fixture();
        profile.reflection = Some(ReflectionProfile {
            ufunction_func_offset: 0xd8,
            ufunction_vtable_va: 0x01a4_8018,
            fframe_locals_offset: Some(0x18),
            fname_pool_blocks_va: Some(0x0c07_b0c0),
            process_event_vtable_slot: Some(77),
            guobjectarray_objects_va: Some(0x0c11_d888),
            super_struct_offset: Some(0x40),
            engine_tick: None,
            admin: None,
            chat: Some(ChatHookFacts {
                broadcast_thunk_rva: 0x0688_19a0,
                fframe_locals_offset: 0x18,
                message_sender_offset: 0x08,
                message_text_offset: 0x28,
            }),
        });
        assert!(profile.validate().is_ok());
        let decoded = BuildProfile::from_toml(&profile.to_toml_pretty().unwrap()).unwrap();
        assert_eq!(profile, decoded);

        profile.reflection = Some(ReflectionProfile {
            ufunction_func_offset: 0,
            ufunction_vtable_va: 0x01a4_8018,
            fframe_locals_offset: None,
            fname_pool_blocks_va: None,
            process_event_vtable_slot: None,
            guobjectarray_objects_va: None,
            super_struct_offset: None,
            engine_tick: None,
            admin: None,
            chat: None,
        });
        assert!(profile.validate().is_err());
    }

    #[test]
    fn byte_pattern_supports_wildcards() {
        let pattern = BytePattern::parse("48 8B ?? 90").unwrap();
        assert!(pattern.matches(&[0x48, 0x8b, 0x01, 0x90]));
        assert!(!pattern.matches(&[0x48, 0x8a, 0x01, 0x90]));
        assert_eq!(pattern.to_string(), "48 8b ?? 90");
    }

    #[test]
    fn toml_round_trip_preserves_profile() {
        let profile = fixture();
        let encoded = profile.to_toml_pretty().unwrap();
        let decoded = BuildProfile::from_toml(&encoded).unwrap();
        assert_eq!(profile, decoded);
    }

    #[test]
    fn shipped_candidate_profile_parses() {
        // The checked-in candidate must always parse + validate (catches schema
        // drift, e.g. the reflection/functions catalog fields).
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../profiles/candidates/palworld-linux-24088465.toml"
        );
        let profile = BuildProfile::read_toml(path).expect("candidate profile must parse");
        let reflection = profile.reflection.expect("candidate has reflection facts");
        assert_eq!(reflection.fframe_locals_offset, Some(0x28));
        assert_eq!(reflection.fname_pool_blocks_va, Some(0x0c07_b0c0));
        assert_eq!(reflection.process_event_vtable_slot, Some(77));
        assert_eq!(reflection.guobjectarray_objects_va, Some(0x0c11_d888));
        assert_eq!(reflection.super_struct_offset, Some(0x40));
        let tick = reflection
            .engine_tick
            .expect("candidate has engine_tick facts");
        assert_eq!(tick.gengine_global_va, 0x0c2a_2b88);
        assert_eq!(tick.tick_vtable_slot, 97);
        let admin = reflection.admin.expect("candidate has admin facts");
        assert_eq!(admin.controller_class, "PalPlayerController");
        assert_eq!(admin.badmin_offset, 0x850);
        assert_eq!(admin.player_state_offset, 0x298);
        assert_eq!(admin.player_uid_offset, 0x590);
        assert_eq!(admin.sender_player_uid_offset, 0x18);
    }
}
