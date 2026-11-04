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
pub const MAIL_PROFILE_VERSION: u32 = 1;
pub const MAIL_COVERAGE_VERSION: u32 = 1;

/// A detector family named by an analysis profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Capability {
    Binary,
    Source,
    Model,
    Media,
    Keystore,
}

pub const MAIL_P0_CAPABILITIES: &[Capability] = &[
    Capability::Binary,
    Capability::Source,
    Capability::Model,
    Capability::Media,
    Capability::Keystore,
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
            version: MAIL_PROFILE_VERSION,
            coverage_version: MAIL_COVERAGE_VERSION,
            capabilities: MAIL_P0_CAPABILITIES,
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
                        detail: Some(if *capability == Capability::Binary {
                            "bounded byte-signature preflight only; complete binary coverage is not wired yet"
                                .to_string()
                        } else {
                            "detector adapter is not wired yet".to_string()
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
            if let Err(stop) = retain_format(&mut report, context, description, evidence) {
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

        Ok(finish(report, context))
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
    description: &str,
    evidence: ByteRange,
) -> Result<(), StopReason> {
    context.charge(Resource::Objects, 1)?;
    context.charge(Resource::RetainedBytes, description.len() as u64)?;
    report.detected_formats.push(DetectedFormat {
        kind: DetectedFormatKind::ExecutableOrLoadableProgram,
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
            AnalysisProfile::mail_p0(),
            pack::current(),
            MAIL_P0_CAPABILITIES,
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
            coverage: MAIL_P0_CAPABILITIES
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
