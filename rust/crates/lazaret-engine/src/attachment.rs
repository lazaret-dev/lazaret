//! Typed, policy-neutral foundations for attachment analysis.
//!
//! This module deliberately does not expose the named-call JSON protocol in
//! [`crate::api`]. A scanner captures one immutable rule pack, and every scan
//! receives an explicit shared budget and cancellation control. Format
//! adapters are added behind this contract rather than changing it per format.

use crate::pack::{self, Pack};
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
    pub coverage: Vec<AnalyzerCoverage>,
    pub incomplete: Vec<IncompleteReason>,
    pub usage: WorkUsage,
    pub redacted: bool,
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
}
