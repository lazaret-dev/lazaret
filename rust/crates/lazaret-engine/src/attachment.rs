//! Typed, policy-neutral foundations for attachment analysis.
//!
//! This module deliberately does not expose the named-call JSON protocol in
//! [`crate::api`]. A scanner captures one immutable rule pack, and every scan
//! receives an explicit shared budget and cancellation control. Format
//! adapters are added behind this contract rather than changing it per format.

use crate::json::Value;
use crate::pack::{self, Pack};
use crate::pystr;
use std::sync::Arc;

pub const API_SCHEMA_VERSION: u32 = 1;
pub const MAIL_PROFILE_ID: &str = "mail-attachment";
pub const MAIL_P0_PROFILE_VERSION: u32 = 1;
pub const MAIL_P0_COVERAGE_VERSION: u32 = 1;
pub const MAIL_PROFILE_VERSION: u32 = 2;
pub const MAIL_COVERAGE_VERSION: u32 = 2;

/// A detector family named by an analysis profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Capability {
    Binary,
    Source,
    Model,
    Media,
    Keystore,
    Document,
}

pub const MAIL_P0_CAPABILITIES: &[Capability] = &[
    Capability::Binary,
    Capability::Source,
    Capability::Model,
    Capability::Media,
    Capability::Keystore,
];

pub const MAIL_P1_CAPABILITIES: &[Capability] = &[
    Capability::Binary,
    Capability::Source,
    Capability::Model,
    Capability::Media,
    Capability::Keystore,
    Capability::Document,
];

/// The declared detector contract against which completeness is measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnalysisProfile {
    pub id: &'static str,
    pub version: u32,
    pub coverage_version: u32,
    pub capabilities: &'static [Capability],
}

impl AnalysisProfile {
    pub const fn mail_p0() -> Self {
        Self {
            id: MAIL_PROFILE_ID,
            version: MAIL_P0_PROFILE_VERSION,
            coverage_version: MAIL_P0_COVERAGE_VERSION,
            capabilities: MAIL_P0_CAPABILITIES,
        }
    }

    /// Gateway profile with bounded structural PDF and OOXML analysis.
    pub const fn mail_p1() -> Self {
        Self {
            id: MAIL_PROFILE_ID,
            version: MAIL_PROFILE_VERSION,
            coverage_version: MAIL_COVERAGE_VERSION,
            capabilities: MAIL_P1_CAPABILITIES,
        }
    }
}

/// Reproducible identity of the immutable rules captured by a scanner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RulePackIdentity {
    pub version: Option<String>,
    pub content_sha256: String,
}

/// A scanner configuration. Constructing it snapshots the current rule pack;
/// a later process-wide pack install cannot alter this scanner.
#[derive(Clone)]
pub struct AttachmentScanner {
    profile: AnalysisProfile,
    pack: Arc<Pack>,
    rule_pack: RulePackIdentity,
    supported: &'static [Capability],
}

impl AttachmentScanner {
    pub fn current(profile: AnalysisProfile) -> Self {
        Self::with_pack(profile, pack::current(), &[])
    }

    pub(crate) fn with_pack(
        profile: AnalysisProfile,
        pack: Arc<Pack>,
        supported: &'static [Capability],
    ) -> Self {
        let rule_pack = RulePackIdentity {
            version: pack.rule_set.clone(),
            content_sha256: pack.content_sha256().to_string(),
        };
        Self {
            profile,
            pack,
            rule_pack,
            supported,
        }
    }

    pub fn from_rule_pack_json(profile: AnalysisProfile, json: &str) -> Result<Self, String> {
        Ok(Self::with_pack(
            profile,
            Arc::new(Pack::from_json(json)?),
            &[],
        ))
    }

    pub fn profile(&self) -> AnalysisProfile {
        self.profile
    }

    pub fn rule_pack(&self) -> &RulePackIdentity {
        &self.rule_pack
    }

    pub fn pack(&self) -> &Pack {
        &self.pack
    }

    pub fn versions(&self) -> VersionInfo {
        VersionInfo {
            api_schema: API_SCHEMA_VERSION,
            profile_id: self.profile.id,
            profile_version: self.profile.version,
            coverage_version: self.profile.coverage_version,
            engine_version: crate::VERSION,
            rule_pack: self.rule_pack.clone(),
            requested: self.profile.capabilities.to_vec(),
            supported: self.supported.to_vec(),
        }
    }

    /// Run the bounded attachment preflight that is available today.
    ///
    /// This stage reports byte-signature findings but deliberately does not
    /// advertise the complete `Binary` capability yet: the remaining binary,
    /// media and keystore loops still need the shared cancellation and budget
    /// threaded through them. Its coverage therefore remains incomplete even
    /// when this preflight itself finishes.
    pub fn scan_whole(
        &self,
        attachment: WholeAttachment<'_>,
        context: &mut ScanContext<'_>,
    ) -> Result<AttachmentReport, ScanArgumentError> {
        validate_metadata(&attachment)?;

        let mut report = AttachmentReport {
            versions: self.versions(),
            input: ReportedInput {
                identity: attachment.identity,
                length: attachment.bytes.len() as u64,
                filename: None,
                declared_media_type: None,
                container_path: None,
            },
            detected_formats: Vec::new(),
            findings: Vec::new(),
            requested_ranges: Vec::new(),
            coverage: self
                .profile
                .capabilities
                .iter()
                .map(|capability| AnalyzerCoverage {
                    capability: *capability,
                    analyzer: analyzer_name(*capability),
                    state: CoverageState::NotRun,
                })
                .collect(),
            incomplete: Vec::new(),
            usage: context.usage(),
            redacted: false,
        };

        let metadata_bytes = attachment.filename.map_or(0, str::len)
            + attachment.declared_media_type.map_or(0, str::len)
            + attachment.container_path.map_or(0, str::len);
        if let Err(stop) = context.charge(Resource::RetainedBytes, metadata_bytes as u64) {
            record_stop(&mut report, context, "metadata", stop);
            return Ok(finish(report, context));
        }
        report.input.filename = attachment.filename.map(str::to_owned);
        report.input.declared_media_type = attachment.declared_media_type.map(str::to_owned);
        report.input.container_path = attachment.container_path.map(str::to_owned);

        for capability in self.profile.capabilities {
            if !self.supported.contains(capability) {
                push_reason(
                    &mut report,
                    context,
                    IncompleteReason {
                        kind: IncompleteKind::Unsupported,
                        analyzer: Some(analyzer_name(*capability)),
                        detail: Some(match *capability {
                            Capability::Binary => "bounded byte-signature preflight only; complete binary coverage is not wired yet".to_string(),
                            Capability::Document => "bounded structural document pass only; cancellation is not yet threaded through archive and PDF inner loops".to_string(),
                            _ => "detector adapter is not wired yet".to_string(),
                        }),
                    },
                );
            }
        }

        if !self.profile.capabilities.contains(&Capability::Binary) {
            return Ok(finish(report, context));
        }
        set_coverage(&mut report, Capability::Binary, CoverageState::Incomplete);

        if let Err(stop) = context.checkpoint() {
            record_stop(&mut report, context, "binary-preflight", stop);
            return Ok(finish(report, context));
        }
        if let Err(stop) = context.charge(Resource::InputBytes, attachment.bytes.len() as u64) {
            record_stop(&mut report, context, "binary-preflight", stop);
            return Ok(finish(report, context));
        }

        let sample_length = self
            .pack
            .usize("_LOOKS_SAMPLE")
            .max(self.pack.usize("_OPAQUE_SAMPLE"))
            .max(self.pack.usize("DISGUISE_SAMPLE_BYTES"))
            .max(512)
            .min(attachment.bytes.len());
        if let Err(stop) = context.charge(Resource::RangeBytes, sample_length as u64) {
            record_stop(&mut report, context, "binary-preflight", stop);
            return Ok(finish(report, context));
        }
        if let Err(stop) = context.charge(Resource::Operations, 1) {
            record_stop(&mut report, context, "binary-preflight", stop);
            return Ok(finish(report, context));
        }

        let sample = &attachment.bytes[..sample_length];
        let evidence = ByteRange {
            offset: 0,
            length: sample_length.min(512) as u64,
        };
        let path = pystr::u(attachment.filename.unwrap_or("attachment"));
        let program = crate::binary::native_program_description(&self.pack, sample);
        if let Some(description) = program.as_ref() {
            if let Err(stop) = retain_format(
                &mut report,
                context,
                DetectedFormatKind::ExecutableOrLoadableProgram,
                description,
                evidence,
            ) {
                record_stop(&mut report, context, "binary-preflight", stop);
                return Ok(finish(report, context));
            }
        }

        let classified = crate::binary::classify_more(
            &self.pack,
            &path,
            sample,
            attachment.bytes.len() as u64,
            "mail",
            true,
            false,
            crate::binary::More::No,
        );
        let issues = match classified {
            crate::binary::Classified::Issue(issue) => vec![issue],
            crate::binary::Classified::Issues(issues) => issues,
            crate::binary::Classified::Quiet => Vec::new(),
            crate::binary::Classified::Need | crate::binary::Classified::Wrapper => {
                push_reason(
                    &mut report,
                    context,
                    IncompleteReason {
                        kind: IncompleteKind::UnavailableInput,
                        analyzer: Some("binary-preflight"),
                        detail: Some(
                            "the classifier requested a later whole-input stage".to_string(),
                        ),
                    },
                );
                Vec::new()
            }
        };
        for issue in issues {
            let Some(finding) = typed_issue(&issue, evidence) else {
                push_reason(
                    &mut report,
                    context,
                    IncompleteReason {
                        kind: IncompleteKind::InternalEngineFailure,
                        analyzer: Some("binary-preflight"),
                        detail: Some(
                            "the binary classifier returned an invalid finding".to_string(),
                        ),
                    },
                );
                return Ok(finish(report, context));
            };
            if let Err(stop) = push_finding(&mut report, context, finding) {
                record_stop(&mut report, context, "binary-preflight", stop);
                return Ok(finish(report, context));
            }
        }

        if program.is_some() {
            for finding in mismatch_findings(&attachment, evidence) {
                if let Err(stop) = push_finding(&mut report, context, finding) {
                    record_stop(&mut report, context, "binary-preflight", stop);
                    return Ok(finish(report, context));
                }
            }
        }

        if self.profile.capabilities.contains(&Capability::Document) {
            set_coverage(&mut report, Capability::Document, CoverageState::Incomplete);
            if let Err(stop) = self.scan_documents(&attachment, context, &mut report) {
                record_stop(&mut report, context, "document", stop);
            }
        }

        Ok(finish(report, context))
    }

    fn scan_documents(
        &self,
        attachment: &WholeAttachment<'_>,
        context: &mut ScanContext<'_>,
        report: &mut AttachmentReport,
    ) -> Result<(), StopReason> {
        scan_pdf(attachment, context, report)?;
        scan_ooxml(&self.pack, attachment, context, report)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionInfo {
    pub api_schema: u32,
    pub profile_id: &'static str,
    pub profile_version: u32,
    pub coverage_version: u32,
    pub engine_version: &'static str,
    pub rule_pack: RulePackIdentity,
    pub requested: Vec<Capability>,
    pub supported: Vec<Capability>,
}

pub const MAX_FILENAME_BYTES: usize = 4_096;
pub const MAX_MEDIA_TYPE_BYTES: usize = 256;
pub const MAX_CONTAINER_PATH_BYTES: usize = 8_192;

/// One immutable, completely supplied attachment. Ranged inputs use
/// [`RangedInput`] and the same [`InputIdentity`] in a later scan stage.
#[derive(Clone, Copy, Debug)]
pub struct WholeAttachment<'a> {
    pub identity: InputIdentity,
    pub bytes: &'a [u8],
    pub filename: Option<&'a str>,
    pub declared_media_type: Option<&'a str>,
    pub container_path: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanArgumentError {
    FilenameTooLong { limit: usize },
    MediaTypeTooLong { limit: usize },
    ContainerPathTooLong { limit: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportedInput {
    pub identity: InputIdentity,
    pub length: u64,
    pub filename: Option<String>,
    pub declared_media_type: Option<String>,
    pub container_path: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DetectedFormatKind {
    ExecutableOrLoadableProgram,
    Pdf,
    WordprocessingDocument,
    SpreadsheetDocument,
    PresentationDocument,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectedFormat {
    pub kind: DetectedFormatKind,
    pub description: String,
    pub evidence: ByteRange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignalClass {
    ExecutableOrLoadableProgram,
    EmbeddedOrNestedContainer,
    CredentialOrPrivateKeyMaterial,
    OpaqueOrUnaccountedPayload,
    NameOrDeclaredTypeMismatch,
    ActiveDocumentContent,
    StructuralAmbiguity,
    EncryptedOrPasswordProtected,
    MalformedOrUnsupportedContent,
    ExternalReference,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentFinding {
    pub rule_id: String,
    pub name: String,
    pub engine_severity: String,
    pub class: SignalClass,
    pub message: String,
    pub evidence: Vec<ByteRange>,
}

/// Caller-chosen identity for one immutable byte snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InputIdentity(pub [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputRange<'a> {
    pub offset: u64,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeRequest {
    pub offset: u64,
    pub length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputError {
    EmptyRange,
    RangeOverflow,
    RangePastEnd,
    RangesOverlapTouchOrAreUnordered,
    RequestPastEnd,
}

/// A canonical, immutable set of ranges from one input. Supplied ranges are
/// ordered, non-empty, non-overlapping and non-adjacent. Callers coalesce
/// touching ranges so an available read is always one borrowed slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangedInput<'a> {
    identity: InputIdentity,
    length: u64,
    ranges: &'a [InputRange<'a>],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RangeRead<'a> {
    /// One borrowed slice that exactly covers the request without copying.
    Available(&'a [u8]),
    /// The first missing subrange. Supplying it and retrying makes progress.
    Need(RangeRequest),
}

impl<'a> RangedInput<'a> {
    pub fn new(
        identity: InputIdentity,
        length: u64,
        ranges: &'a [InputRange<'a>],
    ) -> Result<Self, InputError> {
        let mut end = 0u64;
        for (index, range) in ranges.iter().enumerate() {
            if range.bytes.is_empty() {
                return Err(InputError::EmptyRange);
            }
            let range_end = range
                .offset
                .checked_add(range.bytes.len() as u64)
                .ok_or(InputError::RangeOverflow)?;
            if range_end > length {
                return Err(InputError::RangePastEnd);
            }
            if index != 0 && range.offset <= end {
                return Err(InputError::RangesOverlapTouchOrAreUnordered);
            }
            end = range_end;
        }
        Ok(Self {
            identity,
            length,
            ranges,
        })
    }

    pub fn identity(&self) -> InputIdentity {
        self.identity
    }

    pub fn len(&self) -> u64 {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn ranges(&self) -> &'a [InputRange<'a>] {
        self.ranges
    }

    pub fn read(&self, request: RangeRequest) -> Result<RangeRead<'a>, InputError> {
        let wanted_end = request
            .offset
            .checked_add(request.length)
            .ok_or(InputError::RangeOverflow)?;
        if wanted_end > self.length {
            return Err(InputError::RequestPastEnd);
        }
        if request.length == 0 {
            return Ok(RangeRead::Available(&[]));
        }

        let mut cursor = request.offset;
        for range in self.ranges {
            let range_end = range.offset + range.bytes.len() as u64;
            if range_end <= cursor {
                continue;
            }
            if range.offset > cursor {
                return Ok(RangeRead::Need(RangeRequest {
                    offset: cursor,
                    length: wanted_end.min(range.offset) - cursor,
                }));
            }
            let start = (cursor - range.offset) as usize;
            if wanted_end <= range_end {
                return Ok(RangeRead::Available(
                    &range.bytes[start..start + request.length as usize],
                ));
            }
            cursor = range_end;
        }
        Ok(RangeRead::Need(RangeRequest {
            offset: cursor,
            length: wanted_end - cursor,
        }))
    }
}

/// Host cancellation source. The engine only observes it at documented
/// checkpoints and performs no I/O through it.
pub trait Cancellation: Send + Sync {
    fn is_cancelled(&self) -> bool;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NeverCancelled;

impl Cancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Resource {
    InputBytes,
    RangeBytes,
    DecodedBytes,
    Members,
    Objects,
    Findings,
    IncompleteReasons,
    EvidenceBytes,
    TextCharacters,
    Depth,
    RetainedBytes,
    Operations,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkLimits {
    pub input_bytes: u64,
    pub range_bytes: u64,
    pub decoded_bytes: u64,
    pub members: u64,
    pub objects: u64,
    pub findings: u64,
    pub incomplete_reasons: u64,
    pub evidence_bytes: u64,
    pub text_characters: u64,
    pub depth: u64,
    pub retained_bytes: u64,
    pub operations: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkUsage {
    pub input_bytes: u64,
    pub range_bytes: u64,
    pub decoded_bytes: u64,
    pub members: u64,
    pub objects: u64,
    pub findings: u64,
    pub incomplete_reasons: u64,
    pub evidence_bytes: u64,
    pub text_characters: u64,
    pub max_depth: u64,
    pub retained_bytes: u64,
    pub operations: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitReached {
    pub resource: Resource,
    pub limit: u64,
    pub attempted: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkBudget {
    limits: WorkLimits,
    usage: WorkUsage,
}

impl WorkBudget {
    pub fn new(limits: WorkLimits) -> Self {
        Self {
            limits,
            usage: WorkUsage::default(),
        }
    }

    pub fn limits(&self) -> WorkLimits {
        self.limits
    }

    pub fn usage(&self) -> WorkUsage {
        self.usage
    }

    pub fn charge(&mut self, resource: Resource, amount: u64) -> Result<(), LimitReached> {
        if resource == Resource::Depth {
            return self.observe_depth(amount);
        }
        let limit = self.limit(resource);
        let used = self.used(resource);
        let attempted = used.checked_add(amount).unwrap_or(u64::MAX);
        if attempted > limit {
            return Err(LimitReached {
                resource,
                limit,
                attempted,
            });
        }
        *self.used_mut(resource) = attempted;
        Ok(())
    }

    pub fn observe_depth(&mut self, depth: u64) -> Result<(), LimitReached> {
        if depth > self.limits.depth {
            return Err(LimitReached {
                resource: Resource::Depth,
                limit: self.limits.depth,
                attempted: depth,
            });
        }
        self.usage.max_depth = self.usage.max_depth.max(depth);
        Ok(())
    }

    fn limit(&self, resource: Resource) -> u64 {
        match resource {
            Resource::InputBytes => self.limits.input_bytes,
            Resource::RangeBytes => self.limits.range_bytes,
            Resource::DecodedBytes => self.limits.decoded_bytes,
            Resource::Members => self.limits.members,
            Resource::Objects => self.limits.objects,
            Resource::Findings => self.limits.findings,
            Resource::IncompleteReasons => self.limits.incomplete_reasons,
            Resource::EvidenceBytes => self.limits.evidence_bytes,
            Resource::TextCharacters => self.limits.text_characters,
            Resource::Depth => self.limits.depth,
            Resource::RetainedBytes => self.limits.retained_bytes,
            Resource::Operations => self.limits.operations,
        }
    }

    fn used(&self, resource: Resource) -> u64 {
        match resource {
            Resource::InputBytes => self.usage.input_bytes,
            Resource::RangeBytes => self.usage.range_bytes,
            Resource::DecodedBytes => self.usage.decoded_bytes,
            Resource::Members => self.usage.members,
            Resource::Objects => self.usage.objects,
            Resource::Findings => self.usage.findings,
            Resource::IncompleteReasons => self.usage.incomplete_reasons,
            Resource::EvidenceBytes => self.usage.evidence_bytes,
            Resource::TextCharacters => self.usage.text_characters,
            Resource::Depth => self.usage.max_depth,
            Resource::RetainedBytes => self.usage.retained_bytes,
            Resource::Operations => self.usage.operations,
        }
    }

    fn used_mut(&mut self, resource: Resource) -> &mut u64 {
        match resource {
            Resource::InputBytes => &mut self.usage.input_bytes,
            Resource::RangeBytes => &mut self.usage.range_bytes,
            Resource::DecodedBytes => &mut self.usage.decoded_bytes,
            Resource::Members => &mut self.usage.members,
            Resource::Objects => &mut self.usage.objects,
            Resource::Findings => &mut self.usage.findings,
            Resource::IncompleteReasons => &mut self.usage.incomplete_reasons,
            Resource::EvidenceBytes => &mut self.usage.evidence_bytes,
            Resource::TextCharacters => &mut self.usage.text_characters,
            Resource::Depth => &mut self.usage.max_depth,
            Resource::RetainedBytes => &mut self.usage.retained_bytes,
            Resource::Operations => &mut self.usage.operations,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    Cancelled,
    Limit(LimitReached),
}

/// Mutable state shared by every analyzer and nested operation in one scan.
pub struct ScanContext<'a> {
    cancellation: &'a dyn Cancellation,
    budget: WorkBudget,
}

impl<'a> ScanContext<'a> {
    pub fn new(limits: WorkLimits, cancellation: &'a dyn Cancellation) -> Self {
        Self {
            cancellation,
            budget: WorkBudget::new(limits),
        }
    }

    pub fn checkpoint(&self) -> Result<(), StopReason> {
        if self.cancellation.is_cancelled() {
            Err(StopReason::Cancelled)
        } else {
            Ok(())
        }
    }

    pub fn charge(&mut self, resource: Resource, amount: u64) -> Result<(), StopReason> {
        self.checkpoint()?;
        self.budget
            .charge(resource, amount)
            .map_err(StopReason::Limit)
    }

    pub fn observe_depth(&mut self, depth: u64) -> Result<(), StopReason> {
        self.checkpoint()?;
        self.budget.observe_depth(depth).map_err(StopReason::Limit)
    }

    pub fn usage(&self) -> WorkUsage {
        self.budget.usage()
    }

    pub fn limits(&self) -> WorkLimits {
        self.budget.limits()
    }

    pub fn remaining(&self, resource: Resource) -> u64 {
        self.budget
            .limit(resource)
            .saturating_sub(self.budget.used(resource))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemberIdentity(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberKind {
    File,
    Directory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemberState {
    Available,
    Unsupported,
    ExtractionError,
    UnavailableByLimit,
}

/// One member in the caller's canonical logical-container view.
pub struct ContainerMember<'a> {
    pub identity: MemberIdentity,
    pub canonical_path: &'a str,
    pub aliases: &'a [&'a str],
    pub kind: MemberKind,
    pub state: MemberState,
    pub bytes: Option<RangedInput<'a>>,
}

pub struct ContainerView<'a> {
    pub source: InputIdentity,
    pub complete: bool,
    pub members: &'a [ContainerMember<'a>],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IncompleteKind {
    Unsupported,
    StructurallyAmbiguous,
    Corrupt,
    Truncated,
    UnavailableInput,
    LimitExhausted,
    Cancelled,
    InternalEngineFailure,
    EncryptedOrPasswordProtected,
    ReasonsTruncated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncompleteReason {
    pub kind: IncompleteKind,
    pub analyzer: Option<&'static str>,
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageState {
    Complete,
    Incomplete,
    NotRun,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalyzerCoverage {
    pub capability: Capability,
    pub analyzer: &'static str,
    pub state: CoverageState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentReport {
    pub versions: VersionInfo,
    pub input: ReportedInput,
    pub detected_formats: Vec<DetectedFormat>,
    pub findings: Vec<AttachmentFinding>,
    pub requested_ranges: Vec<RangeRequest>,
    pub coverage: Vec<AnalyzerCoverage>,
    pub incomplete: Vec<IncompleteReason>,
    pub usage: WorkUsage,
    pub redacted: bool,
}

fn document_limits(context: &ScanContext<'_>) -> crate::document::Limits {
    let defaults = crate::document::Limits::default();
    let remaining_operations = context.remaining(Resource::Operations);
    crate::document::Limits {
        max_members: usize::try_from(context.remaining(Resource::Members))
            .unwrap_or(usize::MAX)
            .min(defaults.max_members),
        max_total_member_bytes: context
            .remaining(Resource::DecodedBytes)
            .min(defaults.max_total_member_bytes),
        max_xml_bytes: usize::try_from(context.remaining(Resource::DecodedBytes))
            .unwrap_or(usize::MAX)
            .min(defaults.max_xml_bytes),
        max_xml_tags: usize::try_from(remaining_operations)
            .unwrap_or(usize::MAX)
            .min(defaults.max_xml_tags),
        max_xml_attributes: usize::try_from(remaining_operations.saturating_mul(4))
            .unwrap_or(usize::MAX)
            .min(defaults.max_xml_attributes),
        max_features: usize::try_from(context.remaining(Resource::Findings))
            .unwrap_or(usize::MAX)
            .min(defaults.max_features),
        max_reasons: usize::try_from(context.remaining(Resource::IncompleteReasons))
            .unwrap_or(usize::MAX)
            .min(defaults.max_reasons),
        max_detail_bytes: defaults.max_detail_bytes,
        max_pdf_bytes: usize::try_from(context.remaining(Resource::InputBytes))
            .unwrap_or(usize::MAX)
            .max(context.usage().input_bytes as usize)
            .min(defaults.max_pdf_bytes),
        max_pdf_tokens: usize::try_from(remaining_operations)
            .unwrap_or(usize::MAX)
            .min(defaults.max_pdf_tokens),
    }
}

fn detected_document_kind(kind: crate::document::DocumentKind) -> DetectedFormatKind {
    match kind {
        crate::document::DocumentKind::Pdf => DetectedFormatKind::Pdf,
        crate::document::DocumentKind::Wordprocessing => DetectedFormatKind::WordprocessingDocument,
        crate::document::DocumentKind::Spreadsheet => DetectedFormatKind::SpreadsheetDocument,
        crate::document::DocumentKind::Presentation => DetectedFormatKind::PresentationDocument,
    }
}

fn document_description(kind: crate::document::DocumentKind) -> &'static str {
    match kind {
        crate::document::DocumentKind::Pdf => "PDF document",
        crate::document::DocumentKind::Wordprocessing => "Office Open XML word-processing document",
        crate::document::DocumentKind::Spreadsheet => "Office Open XML spreadsheet",
        crate::document::DocumentKind::Presentation => "Office Open XML presentation",
    }
}

fn document_claim_from_filename(filename: &str) -> Option<crate::document::DocumentKind> {
    let extension = filename
        .rsplit(['/', '\\'])
        .next()
        .and_then(|name| name.rsplit_once('.'))?
        .1
        .to_ascii_lowercase();
    match extension.as_str() {
        "pdf" => Some(crate::document::DocumentKind::Pdf),
        "docx" | "docm" | "dotx" | "dotm" => Some(crate::document::DocumentKind::Wordprocessing),
        "xlsx" | "xlsm" | "xltx" | "xltm" => Some(crate::document::DocumentKind::Spreadsheet),
        "pptx" | "pptm" | "potx" | "potm" | "ppsx" | "ppsm" => {
            Some(crate::document::DocumentKind::Presentation)
        }
        _ => None,
    }
}

fn document_claim_from_media_type(media_type: &str) -> Option<crate::document::DocumentKind> {
    let media_type = media_type
        .split(';')
        .next()
        .unwrap_or(media_type)
        .trim()
        .to_ascii_lowercase();
    if media_type == "application/pdf" {
        Some(crate::document::DocumentKind::Pdf)
    } else if media_type.contains("wordprocessingml") || media_type.contains("msword") {
        Some(crate::document::DocumentKind::Wordprocessing)
    } else if media_type.contains("spreadsheetml") || media_type.contains("ms-excel") {
        Some(crate::document::DocumentKind::Spreadsheet)
    } else if media_type.contains("presentationml") || media_type.contains("ms-powerpoint") {
        Some(crate::document::DocumentKind::Presentation)
    } else {
        None
    }
}

fn document_claims(
    attachment: &WholeAttachment<'_>,
) -> Vec<(&'static str, crate::document::DocumentKind)> {
    let mut claims = Vec::new();
    if let Some(kind) = attachment.filename.and_then(document_claim_from_filename) {
        claims.push(("filename", kind));
    }
    if let Some(kind) = attachment
        .declared_media_type
        .and_then(document_claim_from_media_type)
    {
        claims.push(("declared media type", kind));
    }
    claims
}

fn document_mismatch_finding(
    source: &'static str,
    claimed: crate::document::DocumentKind,
    detected: Option<crate::document::DocumentKind>,
    evidence: ByteRange,
) -> AttachmentFinding {
    let actual = detected.map_or("unrecognized document bytes", document_description);
    AttachmentFinding {
        rule_id: "ATTACHMENT-DOCUMENT-TYPE-MISMATCH".to_string(),
        name: "Document content disagrees with its claimed type".to_string(),
        engine_severity: "INFO".to_string(),
        class: SignalClass::NameOrDeclaredTypeMismatch,
        message: format!(
            "the {source} claims {} but structural inspection found {actual}",
            document_description(claimed)
        ),
        evidence: vec![evidence],
    }
}

fn document_feature_finding(
    feature: &crate::document::Feature,
    evidence: ByteRange,
) -> Option<AttachmentFinding> {
    use crate::document::FeatureKind;
    let (name, class) = match feature.kind {
        FeatureKind::Macro => ("Office macro content", SignalClass::ActiveDocumentContent),
        FeatureKind::ActiveX => ("Office ActiveX content", SignalClass::ActiveDocumentContent),
        FeatureKind::EmbeddedObject => {
            ("Embedded Office object", SignalClass::ActiveDocumentContent)
        }
        FeatureKind::EmbeddedProgram => (
            "Program embedded in a document",
            SignalClass::ExecutableOrLoadableProgram,
        ),
        FeatureKind::ExternalRelationship => (
            "External Office relationship",
            SignalClass::ExternalReference,
        ),
        FeatureKind::PdfJavaScript => ("PDF JavaScript", SignalClass::ActiveDocumentContent),
        FeatureKind::PdfAutomaticAction => {
            ("Automatic PDF action", SignalClass::ActiveDocumentContent)
        }
        FeatureKind::PdfLaunchAction => ("PDF launch action", SignalClass::ActiveDocumentContent),
        FeatureKind::PdfEmbeddedFile => {
            ("File embedded in a PDF", SignalClass::ActiveDocumentContent)
        }
        FeatureKind::PdfXfa => ("PDF XFA content", SignalClass::ActiveDocumentContent),
        FeatureKind::PdfExternalReference => {
            ("External PDF reference", SignalClass::ExternalReference)
        }
        FeatureKind::TrailingData => (
            "Data after the PDF EOF marker",
            SignalClass::StructuralAmbiguity,
        ),
        FeatureKind::IncrementalRevision => (
            "Incrementally revised PDF",
            SignalClass::StructuralAmbiguity,
        ),
        FeatureKind::FeaturesTruncated => return None,
    };
    let mut message = name.to_string();
    if let Some(member) = feature.member.as_deref() {
        message.push_str(" in ");
        message.push_str(member);
    }
    if let Some(detail) = feature.detail.as_deref() {
        message.push_str(": ");
        message.push_str(detail);
    }
    Some(AttachmentFinding {
        rule_id: feature.id.to_string(),
        name: name.to_string(),
        engine_severity: "INFO".to_string(),
        class,
        message,
        evidence: vec![evidence],
    })
}

fn push_document_reason(
    report: &mut AttachmentReport,
    context: &mut ScanContext<'_>,
    reason: &crate::document::Reason,
) {
    use crate::document::ReasonKind;
    let kind = match reason.kind {
        ReasonKind::Malformed => IncompleteKind::Corrupt,
        ReasonKind::Ambiguous => IncompleteKind::StructurallyAmbiguous,
        ReasonKind::Unsupported => IncompleteKind::Unsupported,
        ReasonKind::Encrypted => IncompleteKind::EncryptedOrPasswordProtected,
        ReasonKind::Limit => IncompleteKind::LimitExhausted,
        ReasonKind::Truncated => IncompleteKind::Truncated,
        ReasonKind::ReasonsTruncated => IncompleteKind::ReasonsTruncated,
    };
    let detail = reason.detail.as_ref().map_or_else(
        || reason.component.to_string(),
        |detail| format!("{}: {detail}", reason.component),
    );
    push_reason(
        report,
        context,
        IncompleteReason {
            kind,
            analyzer: Some("document"),
            detail: Some(detail),
        },
    );
}

fn retain_document_report(
    value: &crate::document::DocumentReport,
    context: &mut ScanContext<'_>,
    report: &mut AttachmentReport,
    evidence: ByteRange,
) -> Result<(), StopReason> {
    context.charge(Resource::Operations, value.operations_examined)?;
    if let Some(kind) = value.kind.filter(|_| value.is_confirmed()) {
        retain_format(
            report,
            context,
            detected_document_kind(kind),
            document_description(kind),
            evidence,
        )?;
    }
    for feature in &value.features {
        if feature.kind == crate::document::FeatureKind::FeaturesTruncated {
            push_reason(
                report,
                context,
                IncompleteReason {
                    kind: IncompleteKind::LimitExhausted,
                    analyzer: Some("document"),
                    detail: Some("document feature findings were truncated".to_string()),
                },
            );
        } else if let Some(finding) = document_feature_finding(feature, evidence) {
            push_finding(report, context, finding)?;
        }
    }
    for reason in &value.reasons {
        push_document_reason(report, context, reason);
    }
    Ok(())
}

fn scan_pdf(
    attachment: &WholeAttachment<'_>,
    context: &mut ScanContext<'_>,
    report: &mut AttachmentReport,
) -> Result<(), StopReason> {
    context.charge(Resource::Operations, 1)?;
    let evidence = ByteRange {
        offset: 0,
        length: attachment.bytes.len().min(1024) as u64,
    };
    let value = crate::document::analyze_pdf(attachment.bytes, document_limits(context));
    retain_document_report(&value, context, report, evidence)?;
    if let Some(detected) = value.kind.filter(|_| value.is_confirmed()) {
        for (source, claimed) in document_claims(attachment) {
            if claimed != detected {
                push_finding(
                    report,
                    context,
                    document_mismatch_finding(source, claimed, Some(detected), evidence),
                )?;
            }
        }
    } else if document_claims(attachment)
        .iter()
        .any(|(_, kind)| *kind == crate::document::DocumentKind::Pdf)
    {
        for (source, claimed) in document_claims(attachment)
            .into_iter()
            .filter(|(_, kind)| *kind == crate::document::DocumentKind::Pdf)
        {
            push_finding(
                report,
                context,
                document_mismatch_finding(source, claimed, None, evidence),
            )?;
        }
    }
    Ok(())
}

fn zip_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
}

fn archive_incomplete_kind(error: &lazaret_archive::Error) -> IncompleteKind {
    match error {
        lazaret_archive::Error::Unsupported(_) | lazaret_archive::Error::UnknownFormat => {
            IncompleteKind::Unsupported
        }
        lazaret_archive::Error::Truncated => IncompleteKind::Truncated,
        lazaret_archive::Error::Limit(_) => IncompleteKind::LimitExhausted,
        lazaret_archive::Error::Ambiguous(_) | lazaret_archive::Error::DuplicateEntry(_) => {
            IncompleteKind::StructurallyAmbiguous
        }
        lazaret_archive::Error::Corrupt(_)
        | lazaret_archive::Error::Checksum(_)
        | lazaret_archive::Error::InvalidPath(_) => IncompleteKind::Corrupt,
        _ => IncompleteKind::Unsupported,
    }
}

fn scan_ooxml_member_preflight(
    pack: &Pack,
    archive: &lazaret_archive::Archive,
    context: &mut ScanContext<'_>,
    report: &mut AttachmentReport,
    evidence: ByteRange,
) -> Result<(), StopReason> {
    scan_archive_member_preflight(pack, archive, "", 1, true, context, report, evidence)
}

fn scan_archive_member_preflight(
    pack: &Pack,
    archive: &lazaret_archive::Archive,
    prefix: &str,
    depth: u64,
    document_members: bool,
    context: &mut ScanContext<'_>,
    report: &mut AttachmentReport,
    evidence: ByteRange,
) -> Result<(), StopReason> {
    context.observe_depth(depth)?;
    for entry in archive.entries.iter().filter(|entry| entry.is_file()) {
        context.checkpoint()?;
        context.charge(Resource::Operations, 1)?;
        let separator_length = usize::from(!prefix.is_empty()) * 2;
        let path_length = prefix
            .len()
            .checked_add(separator_length)
            .and_then(|length| length.checked_add(entry.name.len()));
        if path_length.is_none_or(|length| length > MAX_CONTAINER_PATH_BYTES) {
            push_reason(
                report,
                context,
                IncompleteReason {
                    kind: IncompleteKind::LimitExhausted,
                    analyzer: Some("nested-container"),
                    detail: Some("nested member path exceeds the retained-path limit".to_string()),
                },
            );
            continue;
        }
        let member_path = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{prefix}!/{}", entry.name)
        };
        let path = pystr::u(&member_path);
        let classified = crate::binary::classify_more(
            pack,
            &path,
            &entry.data,
            entry.data.len() as u64,
            "mail",
            true,
            false,
            crate::binary::More::Whole(&entry.data),
        );
        let issues = match classified {
            crate::binary::Classified::Issue(issue) => vec![issue],
            crate::binary::Classified::Issues(issues) => issues,
            crate::binary::Classified::Quiet => Vec::new(),
            crate::binary::Classified::Need | crate::binary::Classified::Wrapper => {
                push_reason(
                    report,
                    context,
                    IncompleteReason {
                        kind: IncompleteKind::InternalEngineFailure,
                        analyzer: Some("document-member-preflight"),
                        detail: Some(format!(
                            "whole bytes for {} did not complete byte classification",
                            member_path
                        )),
                    },
                );
                Vec::new()
            }
        };
        for issue in issues {
            let Some(mut finding) = typed_issue(&issue, evidence) else {
                push_reason(
                    report,
                    context,
                    IncompleteReason {
                        kind: IncompleteKind::InternalEngineFailure,
                        analyzer: Some("document-member-preflight"),
                        detail: Some(format!(
                            "byte classification for {} returned an invalid finding",
                            member_path
                        )),
                    },
                );
                continue;
            };
            // The document analyzer already reports native programs with the
            // member path. Keep the generic preflight for the other byte-first
            // classes without emitting a second finding for the same program.
            if document_members && finding.rule_id == "SC-BINARY" {
                continue;
            }
            let nested = finding.rule_id == "SC-NESTED-ARCHIVE";
            finding.message = format!("in {member_path}: {}", finding.message);
            push_finding(report, context, finding)?;
            if nested {
                scan_nested_archive(
                    pack,
                    &entry.data,
                    &member_path,
                    depth.saturating_add(1),
                    context,
                    report,
                    evidence,
                )?;
            }
        }
    }
    Ok(())
}

fn scan_nested_archive(
    pack: &Pack,
    bytes: &[u8],
    path: &str,
    depth: u64,
    context: &mut ScanContext<'_>,
    report: &mut AttachmentReport,
    evidence: ByteRange,
) -> Result<(), StopReason> {
    if let Err(stop) = context.observe_depth(depth) {
        match stop {
            StopReason::Cancelled => return Err(stop),
            StopReason::Limit(limit) => {
                push_reason(
                    report,
                    context,
                    IncompleteReason {
                        kind: IncompleteKind::LimitExhausted,
                        analyzer: Some("nested-container"),
                        detail: Some(format!(
                            "{} depth limit {} would be exceeded by {}",
                            path, limit.limit, limit.attempted
                        )),
                    },
                );
                return Ok(());
            }
        }
    }
    context.checkpoint()?;
    context.charge(Resource::Operations, 1)?;
    let limits = lazaret_archive::Limits {
        max_entries: usize::try_from(context.remaining(Resource::Members)).unwrap_or(usize::MAX),
        max_member_size: context.remaining(Resource::DecodedBytes),
        max_total_size: context.remaining(Resource::DecodedBytes),
        max_name_size: MAX_CONTAINER_PATH_BYTES,
        max_metadata_size: context.remaining(Resource::DecodedBytes).min(1024 * 1024),
    };
    let archive = match lazaret_archive::extract_with_limits(bytes, limits) {
        Ok(archive) => archive,
        Err(error) => {
            push_reason(
                report,
                context,
                IncompleteReason {
                    kind: archive_incomplete_kind(&error),
                    analyzer: Some("nested-container"),
                    detail: Some(format!("{path}: {error}")),
                },
            );
            return Ok(());
        }
    };
    let decoded = archive
        .entries
        .iter()
        .try_fold(0u64, |total, entry| total.checked_add(entry.len() as u64));
    let Some(decoded) = decoded else {
        push_reason(
            report,
            context,
            IncompleteReason {
                kind: IncompleteKind::LimitExhausted,
                analyzer: Some("nested-container"),
                detail: Some(format!("{path}: extracted size overflowed")),
            },
        );
        return Ok(());
    };
    context.charge(Resource::Members, archive.entries.len() as u64)?;
    context.charge(Resource::DecodedBytes, decoded)?;
    if archive.is_path_ambiguous() {
        push_reason(
            report,
            context,
            IncompleteReason {
                kind: IncompleteKind::StructurallyAmbiguous,
                analyzer: Some("nested-container"),
                detail: Some(format!("{path}: archive member paths are ambiguous")),
            },
        );
    }
    scan_archive_member_preflight(
        pack, &archive, path, depth, false, context, report, evidence,
    )
}

fn scan_ooxml(
    pack: &Pack,
    attachment: &WholeAttachment<'_>,
    context: &mut ScanContext<'_>,
    report: &mut AttachmentReport,
) -> Result<(), StopReason> {
    let claims = document_claims(attachment);
    let ooxml_claimed = claims
        .iter()
        .any(|(_, kind)| *kind != crate::document::DocumentKind::Pdf);
    if !zip_magic(attachment.bytes) {
        if ooxml_claimed
            && !report.detected_formats.iter().any(|format| {
                matches!(
                    format.kind,
                    DetectedFormatKind::Pdf
                        | DetectedFormatKind::WordprocessingDocument
                        | DetectedFormatKind::SpreadsheetDocument
                        | DetectedFormatKind::PresentationDocument
                )
            })
        {
            let evidence = ByteRange {
                offset: 0,
                length: attachment.bytes.len().min(4) as u64,
            };
            for (source, claimed) in claims
                .into_iter()
                .filter(|(_, kind)| *kind != crate::document::DocumentKind::Pdf)
            {
                push_finding(
                    report,
                    context,
                    document_mismatch_finding(source, claimed, None, evidence),
                )?;
            }
            push_reason(
                report,
                context,
                IncompleteReason {
                    kind: IncompleteKind::Corrupt,
                    analyzer: Some("document"),
                    detail: Some("the claimed OOXML document has no ZIP signature".to_string()),
                },
            );
        }
        return Ok(());
    }

    context.checkpoint()?;
    context.charge(Resource::Operations, 1)?;
    let archive_limits = lazaret_archive::Limits {
        max_entries: usize::try_from(context.remaining(Resource::Members)).unwrap_or(usize::MAX),
        max_member_size: context.remaining(Resource::DecodedBytes),
        max_total_size: context.remaining(Resource::DecodedBytes),
        max_name_size: MAX_CONTAINER_PATH_BYTES,
        max_metadata_size: context.remaining(Resource::DecodedBytes).min(1024 * 1024),
    };
    let archive = match lazaret_archive::extract_as(
        attachment.bytes,
        lazaret_archive::Format::Zip,
        archive_limits,
    ) {
        Ok(archive) => archive,
        Err(error) => {
            push_reason(
                report,
                context,
                IncompleteReason {
                    kind: archive_incomplete_kind(&error),
                    analyzer: Some("document"),
                    detail: Some(error.to_string()),
                },
            );
            return Ok(());
        }
    };
    let decoded = archive
        .entries
        .iter()
        .try_fold(0u64, |total, entry| total.checked_add(entry.len() as u64));
    let Some(decoded) = decoded else {
        push_reason(
            report,
            context,
            IncompleteReason {
                kind: IncompleteKind::LimitExhausted,
                analyzer: Some("document"),
                detail: Some("the extracted document size overflowed".to_string()),
            },
        );
        return Ok(());
    };
    let analysis_limits = document_limits(context);
    context.charge(Resource::Members, archive.entries.len() as u64)?;
    context.charge(Resource::DecodedBytes, decoded)?;
    let evidence = ByteRange {
        offset: 0,
        length: attachment.bytes.len().min(4) as u64,
    };
    scan_ooxml_member_preflight(pack, &archive, context, report, evidence)?;
    let value = crate::document::analyze_ooxml(&archive, pack, analysis_limits);
    retain_document_report(&value, context, report, evidence)?;
    if let Some(detected) = value.kind.filter(|_| value.is_confirmed()) {
        for (source, claimed) in claims {
            if claimed != detected {
                push_finding(
                    report,
                    context,
                    document_mismatch_finding(source, claimed, Some(detected), evidence),
                )?;
            }
        }
    } else if ooxml_claimed {
        for (source, claimed) in claims
            .into_iter()
            .filter(|(_, kind)| *kind != crate::document::DocumentKind::Pdf)
        {
            push_finding(
                report,
                context,
                document_mismatch_finding(source, claimed, None, evidence),
            )?;
        }
    }
    Ok(())
}

fn validate_metadata(attachment: &WholeAttachment<'_>) -> Result<(), ScanArgumentError> {
    if attachment
        .filename
        .is_some_and(|name| name.len() > MAX_FILENAME_BYTES)
    {
        return Err(ScanArgumentError::FilenameTooLong {
            limit: MAX_FILENAME_BYTES,
        });
    }
    if attachment
        .declared_media_type
        .is_some_and(|media_type| media_type.len() > MAX_MEDIA_TYPE_BYTES)
    {
        return Err(ScanArgumentError::MediaTypeTooLong {
            limit: MAX_MEDIA_TYPE_BYTES,
        });
    }
    if attachment
        .container_path
        .is_some_and(|path| path.len() > MAX_CONTAINER_PATH_BYTES)
    {
        return Err(ScanArgumentError::ContainerPathTooLong {
            limit: MAX_CONTAINER_PATH_BYTES,
        });
    }
    Ok(())
}

fn analyzer_name(capability: Capability) -> &'static str {
    match capability {
        Capability::Binary => "binary",
        Capability::Source => "source",
        Capability::Model => "model",
        Capability::Media => "media",
        Capability::Keystore => "keystore",
        Capability::Document => "document",
    }
}

fn set_coverage(report: &mut AttachmentReport, capability: Capability, state: CoverageState) {
    if let Some(coverage) = report
        .coverage
        .iter_mut()
        .find(|coverage| coverage.capability == capability)
    {
        coverage.state = state;
    }
}

fn push_reason(
    report: &mut AttachmentReport,
    context: &mut ScanContext<'_>,
    reason: IncompleteReason,
) {
    if context
        .budget
        .charge(Resource::IncompleteReasons, 1)
        .is_ok()
    {
        report.incomplete.push(reason);
        return;
    }
    if report
        .incomplete
        .iter()
        .any(|reason| reason.kind == IncompleteKind::ReasonsTruncated)
    {
        return;
    }
    let limit = context.limits().incomplete_reasons as usize;
    if limit != 0 && report.incomplete.len() >= limit {
        report.incomplete.pop();
    }
    report.incomplete.push(IncompleteReason {
        kind: IncompleteKind::ReasonsTruncated,
        analyzer: None,
        detail: None,
    });
}

fn record_stop(
    report: &mut AttachmentReport,
    context: &mut ScanContext<'_>,
    analyzer: &'static str,
    stop: StopReason,
) {
    let (kind, detail) = match stop {
        StopReason::Cancelled => (IncompleteKind::Cancelled, None),
        StopReason::Limit(limit) => (
            IncompleteKind::LimitExhausted,
            Some(format!(
                "{:?} limit {} would be exceeded by {}",
                limit.resource, limit.limit, limit.attempted
            )),
        ),
    };
    push_reason(
        report,
        context,
        IncompleteReason {
            kind,
            analyzer: Some(analyzer),
            detail,
        },
    );
}

fn finish(mut report: AttachmentReport, context: &ScanContext<'_>) -> AttachmentReport {
    report.usage = context.usage();
    report
}

fn retain_format(
    report: &mut AttachmentReport,
    context: &mut ScanContext<'_>,
    kind: DetectedFormatKind,
    description: &str,
    evidence: ByteRange,
) -> Result<(), StopReason> {
    context.charge(Resource::Objects, 1)?;
    context.charge(Resource::RetainedBytes, description.len() as u64)?;
    report.detected_formats.push(DetectedFormat {
        kind,
        description: description.to_string(),
        evidence,
    });
    Ok(())
}

fn typed_issue(issue: &Value, evidence: ByteRange) -> Option<AttachmentFinding> {
    let values = issue.as_arr()?;
    let string = |index: usize| values.get(index)?.as_string();
    let rule_id = string(0)?;
    Some(AttachmentFinding {
        class: match rule_id.as_str() {
            "SC-BINARY" => SignalClass::ExecutableOrLoadableProgram,
            "SC-NESTED-ARCHIVE" => SignalClass::EmbeddedOrNestedContainer,
            "S-SECRET" => SignalClass::CredentialOrPrivateKeyMaterial,
            "SC-OPAQUE-BLOB" => SignalClass::OpaqueOrUnaccountedPayload,
            _ => SignalClass::Other,
        },
        rule_id,
        name: string(1)?,
        engine_severity: string(3)?,
        message: string(4)?,
        evidence: vec![evidence],
    })
}

fn push_finding(
    report: &mut AttachmentReport,
    context: &mut ScanContext<'_>,
    finding: AttachmentFinding,
) -> Result<(), StopReason> {
    let retained = finding.rule_id.len()
        + finding.name.len()
        + finding.engine_severity.len()
        + finding.message.len()
        + finding.evidence.len() * std::mem::size_of::<ByteRange>();
    context.charge(Resource::RetainedBytes, retained as u64)?;
    context.charge(Resource::Findings, 1)?;
    report.findings.push(finding);
    Ok(())
}

fn mismatch_findings(
    attachment: &WholeAttachment<'_>,
    evidence: ByteRange,
) -> Vec<AttachmentFinding> {
    let mut findings = Vec::new();
    if let Some(filename) = attachment
        .filename
        .filter(|name| name_implies_non_program(name))
    {
        findings.push(AttachmentFinding {
            rule_id: "ATTACHMENT-NAME-CONTENT-MISMATCH".to_string(),
            name: "Executable content hidden by its filename".to_string(),
            engine_severity: "INFO".to_string(),
            class: SignalClass::NameOrDeclaredTypeMismatch,
            message: format!(
                "{filename} is named as non-program content but its bytes identify a program"
            ),
            evidence: vec![evidence],
        });
    }
    if let Some(media_type) = attachment
        .declared_media_type
        .filter(|media_type| media_type_implies_non_program(media_type))
    {
        findings.push(AttachmentFinding {
            rule_id: "ATTACHMENT-DECLARED-TYPE-MISMATCH".to_string(),
            name: "Executable content disagrees with its declared media type".to_string(),
            engine_severity: "INFO".to_string(),
            class: SignalClass::NameOrDeclaredTypeMismatch,
            message: format!(
                "the declared media type {media_type} describes non-program content but the bytes identify a program"
            ),
            evidence: vec![evidence],
        });
    }
    findings
}

fn name_implies_non_program(filename: &str) -> bool {
    let basename = filename.rsplit(['/', '\\']).next().unwrap_or(filename);
    let Some((_, extension)) = basename.rsplit_once('.') else {
        return false;
    };
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "txt"
            | "md"
            | "csv"
            | "json"
            | "xml"
            | "html"
            | "htm"
            | "pdf"
            | "rtf"
            | "doc"
            | "docx"
            | "xls"
            | "xlsx"
            | "ppt"
            | "pptx"
            | "odt"
            | "ods"
            | "odp"
            | "jpg"
            | "jpeg"
            | "png"
            | "gif"
            | "webp"
            | "svg"
            | "py"
            | "pyw"
            | "js"
            | "mjs"
            | "cjs"
            | "ts"
            | "tsx"
            | "sh"
            | "bash"
            | "zsh"
            | "ps1"
    )
}

fn media_type_implies_non_program(media_type: &str) -> bool {
    let media_type = media_type
        .split(';')
        .next()
        .unwrap_or(media_type)
        .trim()
        .to_ascii_lowercase();
    media_type.starts_with("text/")
        || media_type.starts_with("image/")
        || media_type.starts_with("audio/")
        || media_type.starts_with("video/")
        || media_type.starts_with("font/")
        || matches!(
            media_type.as_str(),
            "application/pdf"
                | "application/json"
                | "application/xml"
                | "application/zip"
                | "application/rtf"
                | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        )
}

impl AttachmentReport {
    pub fn is_complete(&self) -> bool {
        self.incomplete.is_empty()
            && self.versions.requested.iter().all(|requested| {
                self.versions.supported.contains(requested)
                    && self.coverage.iter().any(|coverage| {
                        coverage.capability == *requested
                            && coverage.state == CoverageState::Complete
                    })
            })
            && self
                .coverage
                .iter()
                .all(|coverage| coverage.state == CoverageState::Complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(n: u64) -> WorkLimits {
        WorkLimits {
            input_bytes: n,
            range_bytes: n,
            decoded_bytes: n,
            members: n,
            objects: n,
            findings: n,
            incomplete_reasons: n,
            evidence_bytes: n,
            text_characters: n,
            depth: n,
            retained_bytes: n,
            operations: n,
        }
    }

    fn pdf(catalog: &str) -> Vec<u8> {
        let mut value =
            format!("%PDF-1.7\n1 0 obj\n<< /Type /Catalog {catalog} >>\nendobj\n").into_bytes();
        let xref = value.len();
        value.extend_from_slice(
            format!(
                "xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Root 1 0 R /Size 2 >>\nstartxref\n{xref}\n%%EOF"
            )
            .as_bytes(),
        );
        value
    }

    fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut central = Vec::new();
        for (name, data) in entries {
            let offset = body.len() as u32;
            let name = name.as_bytes();
            let crc = lazaret_verify::inflate::crc32(0, data);
            body.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00");
            body.extend_from_slice(&crc.to_le_bytes());
            body.extend_from_slice(&(data.len() as u32).to_le_bytes());
            body.extend_from_slice(&(data.len() as u32).to_le_bytes());
            body.extend_from_slice(&(name.len() as u16).to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(name);
            body.extend_from_slice(data);

            central
                .extend_from_slice(b"PK\x01\x02\x1e\x03\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00");
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&(0o100644u32 << 16).to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name);
        }
        let central_offset = body.len();
        let central_size = central.len();
        body.extend_from_slice(&central);
        body.extend_from_slice(b"PK\x05\x06\x00\x00\x00\x00");
        body.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        body.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        body.extend_from_slice(&(central_size as u32).to_le_bytes());
        body.extend_from_slice(&(central_offset as u32).to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body
    }

    #[test]
    fn a_scanner_pins_one_pack_and_reports_its_hash() {
        let first = AttachmentScanner::from_rule_pack_json(
            AnalysisProfile::mail_p0(),
            r#"{"rule_set":"one","values":{}}"#,
        )
        .unwrap();
        let second = AttachmentScanner::from_rule_pack_json(
            AnalysisProfile::mail_p0(),
            r#"{"rule_set":"two","values":{}}"#,
        )
        .unwrap();
        assert_eq!(first.rule_pack().version.as_deref(), Some("one"));
        assert_ne!(
            first.rule_pack().content_sha256,
            second.rule_pack().content_sha256
        );
        assert_eq!(first.versions().requested, MAIL_P0_CAPABILITIES);
        assert!(first.versions().supported.is_empty());
    }

    #[test]
    fn document_analysis_is_an_explicit_p1_contract() {
        let p0 = AnalysisProfile::mail_p0();
        let p1 = AnalysisProfile::mail_p1();
        assert_eq!(p0.version, MAIL_P0_PROFILE_VERSION);
        assert_eq!(p0.coverage_version, MAIL_P0_COVERAGE_VERSION);
        assert!(!p0.capabilities.contains(&Capability::Document));
        assert_eq!(p1.version, MAIL_PROFILE_VERSION);
        assert_eq!(p1.coverage_version, MAIL_COVERAGE_VERSION);
        assert!(p1.capabilities.contains(&Capability::Document));
    }

    #[test]
    fn exact_budget_boundaries_succeed_and_one_over_does_not_spend() {
        let mut budget = WorkBudget::new(limits(5));
        assert_eq!(budget.charge(Resource::DecodedBytes, 5), Ok(()));
        assert_eq!(budget.usage().decoded_bytes, 5);
        assert_eq!(
            budget.charge(Resource::DecodedBytes, 1),
            Err(LimitReached {
                resource: Resource::DecodedBytes,
                limit: 5,
                attempted: 6
            })
        );
        assert_eq!(budget.usage().decoded_bytes, 5);
        assert!(budget.observe_depth(5).is_ok());
        assert!(budget.observe_depth(6).is_err());
        assert_eq!(budget.usage().max_depth, 5);
    }

    struct Cancelled;
    impl Cancellation for Cancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    #[test]
    fn cancellation_is_a_required_checkpoint_and_spends_nothing() {
        let mut context = ScanContext::new(limits(5), &Cancelled);
        assert_eq!(
            context.charge(Resource::Operations, 1),
            Err(StopReason::Cancelled)
        );
        assert_eq!(context.usage(), WorkUsage::default());
    }

    #[test]
    fn ranged_inputs_are_canonical_and_request_the_first_gap() {
        let a = InputRange {
            offset: 0,
            bytes: b"ab",
        };
        let b = InputRange {
            offset: 4,
            bytes: b"ef",
        };
        let ranges = [a, b];
        let input = RangedInput::new(InputIdentity([7; 16]), 6, &ranges).unwrap();
        assert_eq!(
            input.read(RangeRequest {
                offset: 0,
                length: 6
            }),
            Ok(RangeRead::Need(RangeRequest {
                offset: 2,
                length: 2
            }))
        );

        let whole = [InputRange {
            offset: 0,
            bytes: b"abcd",
        }];
        let input = RangedInput::new(InputIdentity([8; 16]), 4, &whole).unwrap();
        assert_eq!(
            input.read(RangeRequest {
                offset: 0,
                length: 4
            }),
            Ok(RangeRead::Available(b"abcd"))
        );

        let overlap = [
            InputRange {
                offset: 0,
                bytes: b"abc",
            },
            InputRange {
                offset: 2,
                bytes: b"de",
            },
        ];
        assert_eq!(
            RangedInput::new(InputIdentity([9; 16]), 4, &overlap),
            Err(InputError::RangesOverlapTouchOrAreUnordered)
        );

        let adjacent = [
            InputRange {
                offset: 0,
                bytes: b"ab",
            },
            InputRange {
                offset: 2,
                bytes: b"cd",
            },
        ];
        assert_eq!(
            RangedInput::new(InputIdentity([10; 16]), 4, &adjacent),
            Err(InputError::RangesOverlapTouchOrAreUnordered)
        );
    }

    #[test]
    fn any_incomplete_reason_or_unfinished_analyzer_prevents_complete() {
        let scanner = AttachmentScanner::with_pack(
            AnalysisProfile::mail_p1(),
            pack::current(),
            MAIL_P1_CAPABILITIES,
        );
        let mut report = AttachmentReport {
            versions: scanner.versions(),
            input: ReportedInput {
                identity: InputIdentity([0; 16]),
                length: 0,
                filename: None,
                declared_media_type: None,
                container_path: None,
            },
            detected_formats: Vec::new(),
            findings: Vec::new(),
            requested_ranges: Vec::new(),
            coverage: MAIL_P1_CAPABILITIES
                .iter()
                .map(|capability| AnalyzerCoverage {
                    capability: *capability,
                    analyzer: "test",
                    state: CoverageState::Complete,
                })
                .collect(),
            incomplete: Vec::new(),
            usage: WorkUsage::default(),
            redacted: false,
        };
        assert!(report.is_complete());
        report.incomplete.push(IncompleteReason {
            kind: IncompleteKind::Cancelled,
            analyzer: Some("media"),
            detail: None,
        });
        assert!(!report.is_complete());
        report.incomplete.clear();
        report.coverage.push(AnalyzerCoverage {
            capability: Capability::Media,
            analyzer: "media",
            state: CoverageState::NotRun,
        });
        assert!(!report.is_complete());

        report.coverage.pop();
        report.versions.supported.pop();
        assert!(!report.is_complete());
    }

    #[test]
    fn executable_bytes_are_typed_and_disagreement_is_separate_evidence() {
        let scanner = AttachmentScanner::current(AnalysisProfile::mail_p0());
        let mut context = ScanContext::new(limits(100_000), &NeverCancelled);
        let report = scanner
            .scan_whole(
                WholeAttachment {
                    identity: InputIdentity([11; 16]),
                    bytes: b"MZ\x90\x00\x03\x00\x00\x00\x04\x00",
                    filename: Some("invoice.pdf"),
                    declared_media_type: Some("application/pdf"),
                    container_path: Some("message/invoice.pdf"),
                },
                &mut context,
            )
            .unwrap();

        assert_eq!(report.detected_formats.len(), 1);
        assert_eq!(
            report.detected_formats[0].kind,
            DetectedFormatKind::ExecutableOrLoadableProgram
        );
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "SC-BINARY"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "ATTACHMENT-NAME-CONTENT-MISMATCH"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "ATTACHMENT-DECLARED-TYPE-MISMATCH"));
        assert!(!report.is_complete());
        assert!(report.incomplete.iter().any(|reason| {
            reason.kind == IncompleteKind::Unsupported && reason.analyzer == Some("binary")
        }));
    }

    #[test]
    fn pdf_structure_and_active_content_are_typed_for_the_gateway() {
        let scanner = AttachmentScanner::current(AnalysisProfile::mail_p1());
        let bytes = pdf("/OpenAction << /S /JavaScript /JS (x) >>");
        let mut context = ScanContext::new(limits(10_000_000), &NeverCancelled);
        let report = scanner
            .scan_whole(
                WholeAttachment {
                    identity: InputIdentity([21; 16]),
                    bytes: &bytes,
                    filename: Some("invoice.pdf"),
                    declared_media_type: Some("application/pdf"),
                    container_path: None,
                },
                &mut context,
            )
            .unwrap();
        assert!(report
            .detected_formats
            .iter()
            .any(|format| format.kind == DetectedFormatKind::Pdf));
        assert!(report.findings.iter().any(|finding| {
            finding.rule_id == "PDF-JAVASCRIPT"
                && finding.class == SignalClass::ActiveDocumentContent
        }));
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "ATTACHMENT-DOCUMENT-TYPE-MISMATCH"));
        assert!(report.usage.operations > 1);
    }

    #[test]
    fn ooxml_structure_confirms_macro_type_and_surfaces_renamed_active_content() {
        let scanner = AttachmentScanner::current(AnalysisProfile::mail_p1());
        let content_types = br#"<Types><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/><Override PartName="/word/renamed.dat" ContentType="application/vnd.ms-office.vbaProject"/></Types>"#;
        let relationships = br#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#;
        let external = br#"<Relationships><Relationship Id="rId2" Type="image" TargetMode="External" Target="https://example.invalid/a.png"/></Relationships>"#;
        let nested = stored_zip(&[(
            "payload.exe",
            b"MZ\x90\x00\x03\x00\x00\x00\x04\x00",
        )]);
        let bytes = stored_zip(&[
            ("[Content_Types].xml", content_types),
            ("_rels/.rels", relationships),
            ("word/document.xml", b"<document/>"),
            ("word/renamed.dat", b"macro"),
            (
                "word/media/preview.dat",
                b"MZ\x90\x00\x03\x00\x00\x00\x04\x00",
            ),
            ("word/media/thumbnail.dat", &nested),
            ("word/_rels/document.xml.rels", external),
        ]);
        let mut context = ScanContext::new(limits(10_000_000), &NeverCancelled);
        let report = scanner
            .scan_whole(
                WholeAttachment {
                    identity: InputIdentity([22; 16]),
                    bytes: &bytes,
                    filename: Some("invoice.docm"),
                    declared_media_type: Some("application/vnd.ms-word.document.macroEnabled.12"),
                    container_path: None,
                },
                &mut context,
            )
            .unwrap();
        assert!(
            report
                .detected_formats
                .iter()
                .any(|format| { format.kind == DetectedFormatKind::WordprocessingDocument }),
            "{report:?}"
        );
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "OOXML-MACRO"));
        assert!(report.findings.iter().any(|finding| {
            finding.rule_id == "OOXML-EMBEDDED-PROGRAM"
                && finding.class == SignalClass::ExecutableOrLoadableProgram
                && finding.message.contains("word/media/preview.dat")
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.rule_id == "OOXML-EXTERNAL-RELATIONSHIP"
                && finding.class == SignalClass::ExternalReference
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.rule_id == "SC-NESTED-ARCHIVE"
                && finding.class == SignalClass::EmbeddedOrNestedContainer
                && finding.message.contains("word/media/thumbnail.dat")
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.rule_id == "SC-BINARY"
                && finding.class == SignalClass::ExecutableOrLoadableProgram
                && finding
                    .message
                    .contains("word/media/thumbnail.dat!/payload.exe")
        }));
        assert!(!report
            .incomplete
            .iter()
            .any(|reason| reason.analyzer == Some("nested-container")));
        assert_eq!(report.usage.members, 8);
        assert_eq!(report.usage.max_depth, 2);
        assert!(report.usage.decoded_bytes > 0);
    }

    #[test]
    fn nested_office_archive_respects_depth_without_hiding_later_members() {
        let scanner = AttachmentScanner::current(AnalysisProfile::mail_p1());
        let inner = stored_zip(&[("payload.bin", b"inert")]);
        let outer = stored_zip(&[("inner.zip", &inner)]);
        let bytes = stored_zip(&[
            (
                "[Content_Types].xml",
                br#"<Types><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#,
            ),
            (
                "_rels/.rels",
                br#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#,
            ),
            ("word/document.xml", b"<document/>"),
            ("word/embedded/outer.zip", &outer),
            ("word/media/after.dat", b"PK\x03\x04not-a-complete-zip"),
        ]);
        let mut work_limits = limits(10_000_000);
        work_limits.depth = 2;
        let mut context = ScanContext::new(work_limits, &NeverCancelled);
        let report = scanner
            .scan_whole(
                WholeAttachment {
                    identity: InputIdentity([24; 16]),
                    bytes: &bytes,
                    filename: Some("depth.docx"),
                    declared_media_type: Some(
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    ),
                    container_path: None,
                },
                &mut context,
            )
            .unwrap();

        assert_eq!(report.usage.max_depth, 2);
        assert!(report.incomplete.iter().any(|reason| {
            reason.kind == IncompleteKind::LimitExhausted
                && reason.analyzer == Some("nested-container")
                && reason.detail.as_deref().is_some_and(|detail| {
                    detail.contains("word/embedded/outer.zip!/inner.zip")
                })
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.rule_id == "SC-NESTED-ARCHIVE"
                && finding.message.contains("word/media/after.dat")
        }));
    }

    #[test]
    fn generic_zip_is_not_a_document_and_false_document_claims_are_reported() {
        let scanner = AttachmentScanner::current(AnalysisProfile::mail_p1());
        let bytes = stored_zip(&[("hello.txt", b"hello")]);
        let mut context = ScanContext::new(limits(10_000_000), &NeverCancelled);
        let report = scanner
            .scan_whole(
                WholeAttachment {
                    identity: InputIdentity([23; 16]),
                    bytes: &bytes,
                    filename: Some("hello.docx"),
                    declared_media_type: None,
                    container_path: None,
                },
                &mut context,
            )
            .unwrap();
        assert!(!report.detected_formats.iter().any(|format| {
            matches!(
                format.kind,
                DetectedFormatKind::Pdf
                    | DetectedFormatKind::WordprocessingDocument
                    | DetectedFormatKind::SpreadsheetDocument
                    | DetectedFormatKind::PresentationDocument
            )
        }));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "ATTACHMENT-DOCUMENT-TYPE-MISMATCH"));
    }

    #[test]
    fn ooxml_member_preflight_obeys_the_shared_depth_limit() {
        let scanner = AttachmentScanner::current(AnalysisProfile::mail_p1());
        let bytes = stored_zip(&[
            (
                "[Content_Types].xml",
                br#"<Types><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#,
            ),
            (
                "_rels/.rels",
                br#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#,
            ),
            ("word/document.xml", b"<document/>"),
        ]);
        let attachment = WholeAttachment {
            identity: InputIdentity([24; 16]),
            bytes: &bytes,
            filename: Some("report.docx"),
            declared_media_type: None,
            container_path: None,
        };

        let mut exact_limits = limits(10_000_000);
        exact_limits.depth = 1;
        let mut exact = ScanContext::new(exact_limits, &NeverCancelled);
        let exact_report = scanner.scan_whole(attachment, &mut exact).unwrap();
        assert_eq!(exact_report.usage.max_depth, 1);
        assert!(exact_report
            .detected_formats
            .iter()
            .any(|format| format.kind == DetectedFormatKind::WordprocessingDocument));

        let mut over_limits = exact_limits;
        over_limits.depth = 0;
        let mut over = ScanContext::new(over_limits, &NeverCancelled);
        let over_report = scanner.scan_whole(attachment, &mut over).unwrap();
        assert!(!over_report.is_complete());
        assert!(over_report.incomplete.iter().any(|reason| {
            reason.kind == IncompleteKind::LimitExhausted
                && reason.analyzer == Some("document")
                && reason
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("Depth"))
        }));
    }

    #[test]
    fn cancellation_and_limits_are_reports_not_clean_answers() {
        let scanner = AttachmentScanner::current(AnalysisProfile::mail_p0());
        let attachment = WholeAttachment {
            identity: InputIdentity([12; 16]),
            bytes: b"MZ\x90\x00\x03\x00\x00\x00\x04\x00",
            filename: Some("tool.exe"),
            declared_media_type: None,
            container_path: None,
        };

        let mut cancelled = ScanContext::new(limits(100_000), &Cancelled);
        let report = scanner.scan_whole(attachment, &mut cancelled).unwrap();
        assert!(report
            .incomplete
            .iter()
            .any(|reason| reason.kind == IncompleteKind::Cancelled));
        assert!(report.findings.is_empty());
        assert!(!report.is_complete());

        let mut tiny = limits(100_000);
        tiny.input_bytes = attachment.bytes.len() as u64 - 1;
        let mut limited = ScanContext::new(tiny, &NeverCancelled);
        let report = scanner.scan_whole(attachment, &mut limited).unwrap();
        assert!(report
            .incomplete
            .iter()
            .any(|reason| reason.kind == IncompleteKind::LimitExhausted));
        assert!(report.findings.is_empty());
        assert!(!report.is_complete());
    }

    #[test]
    fn hostile_metadata_is_a_caller_error_before_work_is_spent() {
        let scanner = AttachmentScanner::current(AnalysisProfile::mail_p0());
        let mut context = ScanContext::new(limits(100_000), &NeverCancelled);
        let long = "x".repeat(MAX_MEDIA_TYPE_BYTES + 1);
        assert_eq!(
            scanner.scan_whole(
                WholeAttachment {
                    identity: InputIdentity([13; 16]),
                    bytes: b"hello",
                    filename: None,
                    declared_media_type: Some(&long),
                    container_path: None,
                },
                &mut context,
            ),
            Err(ScanArgumentError::MediaTypeTooLong {
                limit: MAX_MEDIA_TYPE_BYTES
            })
        );
        assert_eq!(context.usage(), WorkUsage::default());
    }

    #[test]
    fn incompleteness_reasons_are_bounded_with_an_explicit_sentinel() {
        let scanner = AttachmentScanner::current(AnalysisProfile::mail_p0());
        let mut small = limits(100_000);
        small.incomplete_reasons = 1;
        let mut context = ScanContext::new(small, &NeverCancelled);
        let report = scanner
            .scan_whole(
                WholeAttachment {
                    identity: InputIdentity([14; 16]),
                    bytes: b"plain text",
                    filename: Some("note.txt"),
                    declared_media_type: Some("text/plain"),
                    container_path: None,
                },
                &mut context,
            )
            .unwrap();
        assert_eq!(report.incomplete.len(), 1);
        assert_eq!(report.incomplete[0].kind, IncompleteKind::ReasonsTruncated);
        assert_eq!(report.usage.incomplete_reasons, 1);
        assert!(!report.is_complete());
    }
}
