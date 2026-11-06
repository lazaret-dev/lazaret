//! Bounded, policy-neutral structural document analysis.
//!
//! These analyzers identify structure and active capabilities. They do not
//! render content or decide whether mail or a package is allowed, so the same
//! report can be used by the project scanner and the attachment gateway.

use crate::pack::Pack;
use lazaret_archive::{Archive, Entry, Format};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DocumentKind {
    Pdf,
    Wordprocessing,
    Spreadsheet,
    Presentation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum FeatureKind {
    Macro,
    ActiveX,
    EmbeddedObject,
    EmbeddedProgram,
    ExternalRelationship,
    PdfJavaScript,
    PdfAutomaticAction,
    PdfLaunchAction,
    PdfEmbeddedFile,
    PdfXfa,
    PdfExternalReference,
    TrailingData,
    IncrementalRevision,
    FeaturesTruncated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Feature {
    pub id: &'static str,
    pub kind: FeatureKind,
    pub member: Option<String>,
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReasonKind {
    Malformed,
    Ambiguous,
    Unsupported,
    Encrypted,
    Limit,
    Truncated,
    ReasonsTruncated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reason {
    pub kind: ReasonKind,
    pub component: &'static str,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentReport {
    pub kind: Option<DocumentKind>,
    pub main_part: Option<String>,
    pub features: Vec<Feature>,
    pub reasons: Vec<Reason>,
    pub members_examined: u64,
    pub bytes_examined: u64,
    pub operations_examined: u64,
}

impl DocumentReport {
    fn empty() -> Self {
        Self {
            kind: None,
            main_part: None,
            features: Vec::new(),
            reasons: Vec::new(),
            members_examined: 0,
            bytes_examined: 0,
            operations_examined: 0,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.reasons.is_empty()
    }

    pub fn is_confirmed(&self) -> bool {
        self.kind.is_some()
            && !self.reasons.iter().any(|reason| {
                matches!(
                    reason.kind,
                    ReasonKind::Malformed | ReasonKind::Ambiguous | ReasonKind::Truncated
                )
            })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_members: usize,
    pub max_total_member_bytes: u64,
    pub max_xml_bytes: usize,
    pub max_xml_tags: usize,
    pub max_xml_attributes: usize,
    pub max_features: usize,
    pub max_reasons: usize,
    pub max_detail_bytes: usize,
    pub max_pdf_bytes: usize,
    pub max_pdf_tokens: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_members: 20_000,
            max_total_member_bytes: 256 * 1024 * 1024,
            max_xml_bytes: 8 * 1024 * 1024,
            max_xml_tags: 250_000,
            max_xml_attributes: 1_000_000,
            max_features: 1_000,
            max_reasons: 100,
            max_detail_bytes: 512,
            max_pdf_bytes: 256 * 1024 * 1024,
            max_pdf_tokens: 2_000_000,
        }
    }
}

fn clipped(text: &str, maximum: usize) -> String {
    if text.len() <= maximum {
        return text.to_string();
    }
    let mut end = maximum;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

fn add_reason(
    report: &mut DocumentReport,
    limits: Limits,
    kind: ReasonKind,
    component: &'static str,
    detail: Option<String>,
) {
    if report.reasons.len() < limits.max_reasons {
        report.reasons.push(Reason {
            kind,
            component,
            detail: detail.map(|detail| clipped(&detail, limits.max_detail_bytes)),
        });
    } else if !report
        .reasons
        .iter()
        .any(|reason| reason.kind == ReasonKind::ReasonsTruncated)
    {
        if limits.max_reasons != 0 {
            report.reasons.pop();
        }
        report.reasons.push(Reason {
            kind: ReasonKind::ReasonsTruncated,
            component: "document",
            detail: None,
        });
    }
}

fn add_feature(report: &mut DocumentReport, limits: Limits, value: Feature) {
    if report.features.len() < limits.max_features {
        report.features.push(value);
    } else if !report
        .features
        .iter()
        .any(|feature| feature.kind == FeatureKind::FeaturesTruncated)
    {
        if limits.max_features != 0 {
            report.features.pop();
        }
        report.features.push(Feature {
            id: "DOCUMENT-FEATURES-TRUNCATED",
            kind: FeatureKind::FeaturesTruncated,
            member: None,
            detail: None,
        });
    }
}

#[derive(Clone, Debug)]
struct XmlTag {
    name: String,
    attributes: Vec<(String, String)>,
}

impl XmlTag {
    fn local_name(&self) -> &str {
        self.name.rsplit(':').next().unwrap_or(&self.name)
    }

    fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

fn xml_text(data: &[u8], limits: Limits) -> Result<String, ReasonKind> {
    if data.len() > limits.max_xml_bytes {
        return Err(ReasonKind::Limit);
    }
    if data.starts_with(&[0xff, 0xfe]) || data.starts_with(&[0xfe, 0xff]) {
        if (data.len() - 2) % 2 != 0 {
            return Err(ReasonKind::Malformed);
        }
        let little = data.starts_with(&[0xff, 0xfe]);
        let units = data[2..].chunks_exact(2).map(|pair| {
            if little {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        });
        return char::decode_utf16(units)
            .collect::<Result<String, _>>()
            .map_err(|_| ReasonKind::Malformed);
    }
    let data = data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data);
    std::str::from_utf8(data)
        .map(str::to_owned)
        .map_err(|_| ReasonKind::Malformed)
}

fn name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
}

fn entity(value: &str) -> Result<String, ReasonKind> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at + 1..];
        let end = rest.find(';').ok_or(ReasonKind::Malformed)?;
        let item = &rest[..end];
        match item {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            _ if item.starts_with("#x") => out.push(
                u32::from_str_radix(&item[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
                    .ok_or(ReasonKind::Malformed)?,
            ),
            _ if item.starts_with('#') => out.push(
                item[1..]
                    .parse::<u32>()
                    .ok()
                    .and_then(char::from_u32)
                    .ok_or(ReasonKind::Malformed)?,
            ),
            _ => return Err(ReasonKind::Unsupported),
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn xml_tags(data: &[u8], limits: Limits) -> Result<Vec<XmlTag>, ReasonKind> {
    let text = xml_text(data, limits)?;
    if text.contains("<!DOCTYPE") || text.contains("<!ENTITY") {
        return Err(ReasonKind::Unsupported);
    }
    let bytes = text.as_bytes();
    let mut tags = Vec::new();
    let mut attributes = 0usize;
    let mut at = 0usize;
    let mut stack = Vec::<String>::new();
    let mut roots = 0usize;
    while let Some(relative) = bytes[at..].iter().position(|byte| *byte == b'<') {
        at += relative;
        if bytes[at..].starts_with(b"<!--") {
            at += 4 + text[at + 4..].find("-->").ok_or(ReasonKind::Malformed)? + 3;
            continue;
        }
        if bytes[at..].starts_with(b"<![CDATA[") {
            at += 9 + text[at + 9..].find("]]>").ok_or(ReasonKind::Malformed)? + 3;
            continue;
        }
        if bytes[at..].starts_with(b"<?") {
            at += 2 + text[at + 2..].find("?>").ok_or(ReasonKind::Malformed)? + 2;
            continue;
        }
        if bytes.get(at + 1) == Some(&b'/') {
            let close = at
                + 2
                + bytes[at + 2..]
                    .iter()
                    .position(|byte| *byte == b'>')
                    .ok_or(ReasonKind::Malformed)?;
            let name = text[at + 2..close].trim();
            if name.is_empty()
                || !name.bytes().all(name_byte)
                || stack.pop().as_deref() != Some(name)
            {
                return Err(ReasonKind::Malformed);
            }
            at = close + 1;
            continue;
        }
        if bytes.get(at + 1) == Some(&b'!') {
            return Err(ReasonKind::Unsupported);
        }
        let mut end = at + 1;
        let mut quote = None;
        while end < bytes.len() {
            match (quote, bytes[end]) {
                (None, b'\'' | b'"') => quote = Some(bytes[end]),
                (Some(want), got) if want == got => quote = None,
                (None, b'>') => break,
                _ => {}
            }
            end += 1;
        }
        if end == bytes.len() || quote.is_some() {
            return Err(ReasonKind::Malformed);
        }
        let body = &bytes[at + 1..end];
        let mut cursor = 0usize;
        while body.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        let start = cursor;
        while body.get(cursor).is_some_and(|byte| name_byte(*byte)) {
            cursor += 1;
        }
        if cursor == start {
            return Err(ReasonKind::Malformed);
        }
        let name = std::str::from_utf8(&body[start..cursor])
            .map_err(|_| ReasonKind::Malformed)?
            .to_string();
        let mut attrs = Vec::new();
        let self_closing = loop {
            while body.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                cursor += 1;
            }
            if cursor >= body.len() {
                break false;
            }
            if body[cursor] == b'/' {
                cursor += 1;
                while body.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                    cursor += 1;
                }
                if cursor != body.len() {
                    return Err(ReasonKind::Malformed);
                }
                break true;
            }
            let start = cursor;
            while body.get(cursor).is_some_and(|byte| name_byte(*byte)) {
                cursor += 1;
            }
            if cursor == start {
                return Err(ReasonKind::Malformed);
            }
            let key = std::str::from_utf8(&body[start..cursor])
                .map_err(|_| ReasonKind::Malformed)?
                .to_string();
            if attrs.iter().any(|(existing, _)| existing == &key) {
                return Err(ReasonKind::Malformed);
            }
            while body.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                cursor += 1;
            }
            if body.get(cursor) != Some(&b'=') {
                return Err(ReasonKind::Malformed);
            }
            cursor += 1;
            while body.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                cursor += 1;
            }
            let quote = *body.get(cursor).ok_or(ReasonKind::Malformed)?;
            if !matches!(quote, b'\'' | b'"') {
                return Err(ReasonKind::Malformed);
            }
            cursor += 1;
            let start = cursor;
            while body.get(cursor).is_some_and(|byte| *byte != quote) {
                cursor += 1;
            }
            if cursor == body.len() {
                return Err(ReasonKind::Malformed);
            }
            let value =
                std::str::from_utf8(&body[start..cursor]).map_err(|_| ReasonKind::Malformed)?;
            cursor += 1;
            attributes = attributes.checked_add(1).ok_or(ReasonKind::Limit)?;
            if attributes > limits.max_xml_attributes {
                return Err(ReasonKind::Limit);
            }
            attrs.push((key, entity(value)?));
        };
        if stack.is_empty() {
            roots = roots.checked_add(1).ok_or(ReasonKind::Limit)?;
            if roots > 1 {
                return Err(ReasonKind::Malformed);
            }
        }
        if !self_closing {
            stack.push(name.clone());
            if stack.len() > limits.max_xml_tags {
                return Err(ReasonKind::Limit);
            }
        }
        tags.push(XmlTag {
            name,
            attributes: attrs,
        });
        if tags.len() > limits.max_xml_tags {
            return Err(ReasonKind::Limit);
        }
        at = end + 1;
    }
    if roots != 1 || !stack.is_empty() {
        return Err(ReasonKind::Malformed);
    }
    Ok(tags)
}

fn xml_failure(
    report: &mut DocumentReport,
    limits: Limits,
    component: &'static str,
    kind: ReasonKind,
) {
    let detail = match kind {
        ReasonKind::Limit => "the XML exceeded its structural limit",
        ReasonKind::Unsupported => "the XML uses an unsupported declaration or entity",
        _ => "the XML is malformed",
    };
    add_reason(report, limits, kind, component, Some(detail.to_string()));
}

fn member_map<'a>(archive: &'a Archive) -> BTreeMap<&'a str, &'a Entry> {
    archive
        .entries
        .iter()
        .filter(|entry| entry.is_file())
        .map(|entry| (entry.name.as_str(), entry))
        .collect()
}

fn relationship_target(target: &str) -> Result<String, ReasonKind> {
    let target = target.trim_start_matches('/');
    if target.is_empty()
        || target.contains('\\')
        || target.contains('?')
        || target.contains('#')
        || target.contains(':')
    {
        return Err(ReasonKind::Malformed);
    }
    let mut parts = Vec::new();
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err(ReasonKind::Ambiguous),
            part => parts.push(part),
        }
    }
    if parts.is_empty() {
        return Err(ReasonKind::Malformed);
    }
    Ok(parts.join("/"))
}

fn main_kind(content_type: &str) -> Option<DocumentKind> {
    let lower = content_type.to_ascii_lowercase();
    if lower.contains("wordprocessingml") && lower.ends_with(".main+xml") {
        Some(DocumentKind::Wordprocessing)
    } else if matches!(
        lower.as_str(),
        "application/vnd.ms-word.document.macroenabled.main+xml"
            | "application/vnd.ms-word.template.macroenabledtemplate.main+xml"
    ) {
        Some(DocumentKind::Wordprocessing)
    } else if lower.contains("spreadsheetml") && lower.ends_with(".main+xml") {
        Some(DocumentKind::Spreadsheet)
    } else if matches!(
        lower.as_str(),
        "application/vnd.ms-excel.sheet.macroenabled.main+xml"
            | "application/vnd.ms-excel.template.macroenabled.main+xml"
            | "application/vnd.ms-excel.addin.macroenabled.main+xml"
    ) {
        Some(DocumentKind::Spreadsheet)
    } else if lower.contains("presentationml") && lower.ends_with(".main+xml") {
        Some(DocumentKind::Presentation)
    } else if matches!(
        lower.as_str(),
        "application/vnd.ms-powerpoint.presentation.macroenabled.main+xml"
            | "application/vnd.ms-powerpoint.slideshow.macroenabled.main+xml"
            | "application/vnd.ms-powerpoint.template.macroenabled.main+xml"
            | "application/vnd.ms-powerpoint.addin.macroenabled.main+xml"
    ) {
        Some(DocumentKind::Presentation)
    } else {
        None
    }
}

fn expected_prefix(kind: DocumentKind) -> &'static str {
    match kind {
        DocumentKind::Wordprocessing => "word/",
        DocumentKind::Spreadsheet => "xl/",
        DocumentKind::Presentation => "ppt/",
        DocumentKind::Pdf => "",
    }
}

fn ooxml_feature(
    report: &mut DocumentReport,
    limits: Limits,
    seen: &mut BTreeSet<(FeatureKind, String)>,
    kind: FeatureKind,
    id: &'static str,
    member: &str,
    detail: Option<String>,
) {
    if seen.insert((kind, member.to_string())) {
        add_feature(
            report,
            limits,
            Feature {
                id,
                kind,
                member: Some(clipped(member, limits.max_detail_bytes)),
                detail,
            },
        );
    }
}

fn part_extension(part: &str) -> Option<&str> {
    let name = part.rsplit('/').next()?;
    let (_, extension) = name.rsplit_once('.')?;
    (!extension.is_empty()).then_some(extension)
}

fn part_content_type<'a>(
    part: &str,
    overrides: &'a BTreeMap<String, String>,
    defaults: &'a BTreeMap<String, String>,
) -> Option<&'a str> {
    overrides.get(part).map(String::as_str).or_else(|| {
        let extension = part_extension(part)?.to_ascii_lowercase();
        defaults.get(&extension).map(String::as_str)
    })
}

/// Identify and inspect an extracted Office Open XML package.
///
/// A generic ZIP is deliberately not identified as OOXML. Confirmation needs
/// both package metadata files, one internal office-document relationship, a
/// matching main-part content type, and the main part itself.
pub fn analyze_ooxml(archive: &Archive, pack: &Pack, limits: Limits) -> DocumentReport {
    let mut report = DocumentReport::empty();
    if archive.format != Format::Zip {
        return report;
    }

    let members = member_map(archive);
    let content_types = members.get("[Content_Types].xml").copied();
    let root_relationships = members.get("_rels/.rels").copied();
    if content_types.is_none() && root_relationships.is_none() {
        return report;
    }
    if archive.entries.len() > limits.max_members {
        add_reason(
            &mut report,
            limits,
            ReasonKind::Limit,
            "package",
            Some("the package has too many members".to_string()),
        );
    }
    let total = archive
        .entries
        .iter()
        .try_fold(0u64, |sum, entry| sum.checked_add(entry.len() as u64));
    match total {
        Some(total) => {
            report.bytes_examined = total.min(limits.max_total_member_bytes);
            if total > limits.max_total_member_bytes {
                add_reason(
                    &mut report,
                    limits,
                    ReasonKind::Limit,
                    "package",
                    Some("the package's extracted members are too large".to_string()),
                );
            }
        }
        None => add_reason(
            &mut report,
            limits,
            ReasonKind::Limit,
            "package",
            Some("the package's extracted size overflowed".to_string()),
        ),
    }
    report.members_examined = archive.entries.len().min(limits.max_members) as u64;
    if archive.is_path_ambiguous() {
        add_reason(
            &mut report,
            limits,
            ReasonKind::Ambiguous,
            "package-paths",
            Some("members collide or have platform-dependent paths".to_string()),
        );
    }

    if content_types.is_none() || root_relationships.is_none() {
        add_reason(
            &mut report,
            limits,
            ReasonKind::Malformed,
            "package",
            Some("OOXML package metadata is incomplete".to_string()),
        );
    }

    let content_tags = match content_types {
        Some(content_types) => match xml_tags(&content_types.data, limits) {
            Ok(tags) => tags,
            Err(kind) => {
                xml_failure(&mut report, limits, "content-types", kind);
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    report.operations_examined = report
        .operations_examined
        .saturating_add(content_tags.len() as u64);
    let mut overrides = BTreeMap::<String, String>::new();
    let mut defaults = BTreeMap::<String, String>::new();
    for tag in &content_tags {
        match tag.local_name() {
            "Override" => {
                let (Some(part), Some(content_type)) =
                    (tag.attribute("PartName"), tag.attribute("ContentType"))
                else {
                    add_reason(
                        &mut report,
                        limits,
                        ReasonKind::Malformed,
                        "content-types",
                        Some("an Override is missing PartName or ContentType".to_string()),
                    );
                    continue;
                };
                let part = match relationship_target(part) {
                    Ok(part) => part,
                    Err(kind) => {
                        add_reason(
                            &mut report,
                            limits,
                            kind,
                            "content-types",
                            Some("an Override has a non-canonical PartName".to_string()),
                        );
                        continue;
                    }
                };
                if let Some(previous) = overrides.insert(part.clone(), content_type.to_string()) {
                    if previous != content_type {
                        add_reason(
                            &mut report,
                            limits,
                            ReasonKind::Ambiguous,
                            "content-types",
                            Some(format!("the part /{part} has conflicting content types")),
                        );
                    }
                }
            }
            "Default" => {
                let (Some(extension), Some(content_type)) =
                    (tag.attribute("Extension"), tag.attribute("ContentType"))
                else {
                    add_reason(
                        &mut report,
                        limits,
                        ReasonKind::Malformed,
                        "content-types",
                        Some("a Default is missing Extension or ContentType".to_string()),
                    );
                    continue;
                };
                if extension.is_empty()
                    || extension.contains(['/', '\\'])
                    || extension.contains('.')
                {
                    add_reason(
                        &mut report,
                        limits,
                        ReasonKind::Malformed,
                        "content-types",
                        Some("a Default has a non-canonical Extension".to_string()),
                    );
                    continue;
                }
                let extension = extension.to_ascii_lowercase();
                if let Some(previous) = defaults.insert(extension.clone(), content_type.to_string())
                {
                    if previous != content_type {
                        add_reason(
                            &mut report,
                            limits,
                            ReasonKind::Ambiguous,
                            "content-types",
                            Some(format!(
                                "the extension .{extension} has conflicting content types"
                            )),
                        );
                    }
                }
            }
            _ => {}
        }
    }

    let relationship_tags = match root_relationships {
        Some(root_relationships) => match xml_tags(&root_relationships.data, limits) {
            Ok(tags) => tags,
            Err(kind) => {
                xml_failure(&mut report, limits, "root-relationships", kind);
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    report.operations_examined = report
        .operations_examined
        .saturating_add(relationship_tags.len() as u64);
    let mut ids = BTreeSet::new();
    let mut main_targets = Vec::new();
    for tag in relationship_tags
        .iter()
        .filter(|tag| tag.local_name() == "Relationship")
    {
        let Some(id) = tag.attribute("Id") else {
            add_reason(
                &mut report,
                limits,
                ReasonKind::Malformed,
                "root-relationships",
                Some("a relationship has no Id".to_string()),
            );
            continue;
        };
        if !ids.insert(id.to_string()) {
            add_reason(
                &mut report,
                limits,
                ReasonKind::Ambiguous,
                "root-relationships",
                Some(format!("relationship Id {id} occurs more than once")),
            );
        }
        let Some(relation_type) = tag.attribute("Type") else {
            continue;
        };
        if !relation_type
            .to_ascii_lowercase()
            .ends_with("/officedocument")
        {
            continue;
        }
        if tag
            .attribute("TargetMode")
            .is_some_and(|mode| mode.eq_ignore_ascii_case("external"))
        {
            add_reason(
                &mut report,
                limits,
                ReasonKind::Malformed,
                "root-relationships",
                Some("the main office document is an external target".to_string()),
            );
            continue;
        }
        let Some(target) = tag.attribute("Target") else {
            add_reason(
                &mut report,
                limits,
                ReasonKind::Malformed,
                "root-relationships",
                Some("the officeDocument relationship has no Target".to_string()),
            );
            continue;
        };
        match relationship_target(target) {
            Ok(target) => main_targets.push(target),
            Err(kind) => add_reason(
                &mut report,
                limits,
                kind,
                "root-relationships",
                Some("the main-part target is not canonical".to_string()),
            ),
        }
    }
    let main_part = if main_targets.len() == 1 {
        main_targets.pop()
    } else {
        add_reason(
            &mut report,
            limits,
            if main_targets.len() > 1 {
                ReasonKind::Ambiguous
            } else {
                ReasonKind::Malformed
            },
            "root-relationships",
            Some(format!(
                "expected one internal officeDocument relationship, found {}",
                main_targets.len()
            )),
        );
        None
    };

    if let Some(main_part) = main_part {
        report.main_part = Some(main_part.clone());
        if let Some(content_type) = part_content_type(&main_part, &overrides, &defaults) {
            if let Some(kind) = main_kind(content_type) {
                report.kind = Some(kind);
                if !main_part.starts_with(expected_prefix(kind)) {
                    add_reason(
                        &mut report,
                        limits,
                        ReasonKind::Ambiguous,
                        "main-part",
                        Some(format!(
                            "the {:?} main part is outside {}",
                            kind,
                            expected_prefix(kind)
                        )),
                    );
                }
            } else {
                add_reason(
                    &mut report,
                    limits,
                    ReasonKind::Unsupported,
                    "main-part",
                    Some(format!("unsupported main-part content type {content_type}")),
                );
            }
        } else {
            add_reason(
                &mut report,
                limits,
                ReasonKind::Malformed,
                "content-types",
                Some(format!("the main part /{main_part} has no content type")),
            );
        }
        if !members.contains_key(main_part.as_str()) {
            add_reason(
                &mut report,
                limits,
                ReasonKind::Malformed,
                "main-part",
                Some(format!("the main part /{main_part} is missing")),
            );
        }
    }

    let vba_parts: BTreeSet<_> = overrides
        .iter()
        .filter(|(_, content_type)| {
            content_type.eq_ignore_ascii_case("application/vnd.ms-office.vbaProject")
        })
        .map(|(part, _)| part.to_ascii_lowercase())
        .collect();
    let vba_extensions: BTreeSet<_> = defaults
        .iter()
        .filter(|(_, content_type)| {
            content_type.eq_ignore_ascii_case("application/vnd.ms-office.vbaProject")
        })
        .map(|(extension, _)| extension.as_str())
        .collect();
    let mut seen = BTreeSet::new();
    for entry in archive
        .entries
        .iter()
        .filter(|entry| entry.is_file())
        .take(limits.max_members)
    {
        report.operations_examined = report.operations_examined.saturating_add(1);
        let lower = entry.name.to_ascii_lowercase();
        let extension_is_vba =
            part_extension(&lower).is_some_and(|extension| vba_extensions.contains(extension));
        if lower.ends_with("/vbaproject.bin") || vba_parts.contains(&lower) || extension_is_vba {
            ooxml_feature(
                &mut report,
                limits,
                &mut seen,
                FeatureKind::Macro,
                "OOXML-MACRO",
                &entry.name,
                None,
            );
        }
        if lower.contains("/activex/") {
            ooxml_feature(
                &mut report,
                limits,
                &mut seen,
                FeatureKind::ActiveX,
                "OOXML-ACTIVEX",
                &entry.name,
                None,
            );
        }
        if lower.contains("/embeddings/") {
            ooxml_feature(
                &mut report,
                limits,
                &mut seen,
                FeatureKind::EmbeddedObject,
                "OOXML-EMBEDDED-OBJECT",
                &entry.name,
                None,
            );
        }
        if crate::binary::native_program(pack, &entry.data) {
            ooxml_feature(
                &mut report,
                limits,
                &mut seen,
                FeatureKind::EmbeddedProgram,
                "OOXML-EMBEDDED-PROGRAM",
                &entry.name,
                None,
            );
        }
        if !lower.ends_with(".rels") {
            continue;
        }
        let tags = match xml_tags(&entry.data, limits) {
            Ok(tags) => tags,
            Err(kind) => {
                xml_failure(&mut report, limits, "relationships", kind);
                continue;
            }
        };
        report.operations_examined = report.operations_examined.saturating_add(tags.len() as u64);
        for tag in tags.iter().filter(|tag| tag.local_name() == "Relationship") {
            let relation_type = tag.attribute("Type").unwrap_or_default();
            if relation_type.to_ascii_lowercase().ends_with("/vbaproject") {
                let detail = tag
                    .attribute("Target")
                    .map(|target| clipped(target, limits.max_detail_bytes));
                ooxml_feature(
                    &mut report,
                    limits,
                    &mut seen,
                    FeatureKind::Macro,
                    "OOXML-MACRO",
                    &entry.name,
                    detail,
                );
            }
            if !tag
                .attribute("TargetMode")
                .is_some_and(|mode| mode.eq_ignore_ascii_case("external"))
            {
                continue;
            }
            let detail = tag
                .attribute("Target")
                .map(|target| clipped(target, limits.max_detail_bytes));
            ooxml_feature(
                &mut report,
                limits,
                &mut seen,
                FeatureKind::ExternalRelationship,
                "OOXML-EXTERNAL-RELATIONSHIP",
                &entry.name,
                detail,
            );
        }
    }
    report
}

fn positions(data: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > data.len() {
        return Vec::new();
    }
    data.windows(needle.len())
        .enumerate()
        .filter_map(|(at, value)| (value == needle).then_some(at))
        .collect()
}

fn pdf_delimiter(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(
            byte,
            b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
        )
}

fn pdf_name(raw: &[u8]) -> String {
    let mut value = Vec::with_capacity(raw.len());
    let mut at = 0;
    while at < raw.len() {
        if raw[at] == b'#' && at + 2 < raw.len() {
            let hex = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                b'A'..=b'F' => Some(byte - b'A' + 10),
                _ => None,
            };
            if let (Some(high), Some(low)) = (hex(raw[at + 1]), hex(raw[at + 2])) {
                value.push(high * 16 + low);
                at += 3;
                continue;
            }
        }
        value.push(raw[at]);
        at += 1;
    }
    String::from_utf8_lossy(&value).into_owned()
}

fn find_from(data: &[u8], start: usize, needle: &[u8]) -> Option<usize> {
    data.get(start..)?
        .windows(needle.len())
        .position(|value| value == needle)
        .map(|relative| start + relative)
}

fn pdf_names(data: &[u8], limits: Limits) -> Result<(BTreeSet<String>, usize, bool), ReasonKind> {
    let mut names = BTreeSet::new();
    let mut tokens = 0usize;
    let mut dictionaries = 0usize;
    let mut stream_boundaries_unverified = false;
    let mut at = 0usize;
    while at < data.len() {
        if data[at].is_ascii_whitespace() {
            at += 1;
            continue;
        }
        if data[at] == b'%' {
            at += 1;
            while at < data.len() && !matches!(data[at], b'\r' | b'\n') {
                at += 1;
            }
            continue;
        }
        tokens = tokens.checked_add(1).ok_or(ReasonKind::Limit)?;
        if tokens > limits.max_pdf_tokens {
            return Err(ReasonKind::Limit);
        }
        match data[at] {
            b'(' => {
                let mut depth = 1usize;
                at += 1;
                while at < data.len() && depth != 0 {
                    match data[at] {
                        b'\\' => at = (at + 2).min(data.len()),
                        b'(' => {
                            depth += 1;
                            at += 1;
                        }
                        b')' => {
                            depth -= 1;
                            at += 1;
                        }
                        _ => at += 1,
                    }
                }
                if depth != 0 {
                    return Err(ReasonKind::Malformed);
                }
            }
            b'<' if data.get(at + 1) == Some(&b'<') => {
                dictionaries = dictionaries.checked_add(1).ok_or(ReasonKind::Limit)?;
                at += 2;
            }
            b'>' if data.get(at + 1) == Some(&b'>') => {
                dictionaries = dictionaries.checked_sub(1).ok_or(ReasonKind::Malformed)?;
                at += 2;
            }
            b'<' => {
                at += 1;
                while at < data.len() && data[at] != b'>' {
                    at += 1;
                }
                if at == data.len() {
                    return Err(ReasonKind::Malformed);
                }
                at += 1;
            }
            b'/' => {
                let start = at + 1;
                at = start;
                while at < data.len() && !pdf_delimiter(data[at]) {
                    at += 1;
                }
                if at > start {
                    names.insert(pdf_name(&data[start..at]));
                }
            }
            byte if pdf_delimiter(byte) => at += 1,
            _ => {
                let start = at;
                while at < data.len() && !pdf_delimiter(data[at]) {
                    at += 1;
                }
                if &data[start..at] == b"stream" {
                    stream_boundaries_unverified = true;
                    if data.get(at..at + 2) == Some(b"\r\n") {
                        at += 2;
                    } else if data
                        .get(at)
                        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
                    {
                        at += 1;
                    }
                    at = find_from(data, at, b"endstream").ok_or(ReasonKind::Truncated)?
                        + b"endstream".len();
                }
            }
        }
    }
    if dictionaries != 0 {
        return Err(ReasonKind::Malformed);
    }
    Ok((names, tokens, stream_boundaries_unverified))
}

fn add_pdf_feature(
    report: &mut DocumentReport,
    limits: Limits,
    kind: FeatureKind,
    id: &'static str,
    detail: &'static str,
) {
    add_feature(
        report,
        limits,
        Feature {
            id,
            kind,
            member: None,
            detail: Some(detail.to_string()),
        },
    );
}

/// Identify and conservatively inspect one PDF byte stream.
///
/// The pass validates the header, final EOF marker and final cross-reference
/// target. It tokenizes dictionaries outside apparent content streams, so text
/// painted on a page is not confused with an active PDF name. Any stream keeps
/// the report incomplete until `/Length`-based stream framing and decoding are
/// implemented; object streams are likewise reported as unsupported.
pub fn analyze_pdf(data: &[u8], limits: Limits) -> DocumentReport {
    let mut report = DocumentReport::empty();
    let header_window = &data[..data.len().min(1024)];
    let headers = positions(header_window, b"%PDF-");
    if headers.is_empty() {
        return report;
    }
    report.kind = Some(DocumentKind::Pdf);
    report.bytes_examined = data.len().min(limits.max_pdf_bytes) as u64;
    if data.len() > limits.max_pdf_bytes {
        add_reason(
            &mut report,
            limits,
            ReasonKind::Limit,
            "pdf",
            Some("the PDF exceeds the inspection byte limit".to_string()),
        );
        return report;
    }
    if headers.len() != 1 {
        add_reason(
            &mut report,
            limits,
            ReasonKind::Ambiguous,
            "pdf-header",
            Some("more than one PDF header occurs in the header window".to_string()),
        );
    }
    let version = data.get(headers[0] + 5..headers[0] + 8);
    if !version.is_some_and(|version| {
        version.len() == 3
            && matches!(version[0], b'1' | b'2')
            && version[1] == b'.'
            && version[2].is_ascii_digit()
    }) {
        add_reason(
            &mut report,
            limits,
            ReasonKind::Malformed,
            "pdf-header",
            Some("the PDF version is malformed".to_string()),
        );
    }

    let eof = positions(data, b"%%EOF");
    let startxrefs = positions(data, b"startxref");
    if eof.len() > 1 || startxrefs.len() > 1 {
        add_pdf_feature(
            &mut report,
            limits,
            FeatureKind::IncrementalRevision,
            "PDF-INCREMENTAL-REVISION",
            "the PDF has more than one cross-reference or EOF revision",
        );
    }
    let Some(&final_eof) = eof.last() else {
        add_reason(
            &mut report,
            limits,
            ReasonKind::Truncated,
            "pdf-eof",
            Some("the PDF has no final %%EOF marker".to_string()),
        );
        return report;
    };
    if data[final_eof + b"%%EOF".len()..]
        .iter()
        .any(|byte| !byte.is_ascii_whitespace())
    {
        add_pdf_feature(
            &mut report,
            limits,
            FeatureKind::TrailingData,
            "PDF-TRAILING-DATA",
            "non-whitespace bytes follow the final %%EOF marker",
        );
    }
    let Some(&startxref) = startxrefs.iter().rev().find(|at| **at < final_eof) else {
        add_reason(
            &mut report,
            limits,
            ReasonKind::Malformed,
            "pdf-xref",
            Some("the PDF has no startxref before its final EOF".to_string()),
        );
        return report;
    };
    let mut at = startxref + b"startxref".len();
    while data.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    let number_start = at;
    let mut offset = 0usize;
    while data.get(at).is_some_and(u8::is_ascii_digit) {
        offset = match offset
            .checked_mul(10)
            .and_then(|value| value.checked_add((data[at] - b'0') as usize))
        {
            Some(value) => value,
            None => {
                add_reason(
                    &mut report,
                    limits,
                    ReasonKind::Malformed,
                    "pdf-xref",
                    Some("the startxref offset overflowed".to_string()),
                );
                return report;
            }
        };
        at += 1;
    }
    if at == number_start || offset >= data.len() {
        add_reason(
            &mut report,
            limits,
            ReasonKind::Malformed,
            "pdf-xref",
            Some("the final startxref offset is invalid".to_string()),
        );
    } else {
        let target = &data[offset..data.len().min(offset.saturating_add(4096))];
        let table = target.starts_with(b"xref")
            && target.get(4).is_none_or(|byte| byte.is_ascii_whitespace());
        let stream = positions(target, b"/Type").into_iter().any(|type_at| {
            target[type_at + 5..].starts_with(b" /XRef")
                || target[type_at + 5..].starts_with(b"/XRef")
        });
        if !table && !stream {
            add_reason(
                &mut report,
                limits,
                ReasonKind::Malformed,
                "pdf-xref",
                Some("startxref does not identify an xref table or xref stream".to_string()),
            );
        }
    }

    let (names, stream_boundaries_unverified) = match pdf_names(data, limits) {
        Ok((names, tokens, stream_boundaries_unverified)) => {
            report.operations_examined = tokens as u64;
            (names, stream_boundaries_unverified)
        }
        Err(kind) => {
            add_reason(
                &mut report,
                limits,
                kind,
                "pdf-objects",
                Some(
                    match kind {
                        ReasonKind::Limit => "the PDF token limit was reached",
                        ReasonKind::Truncated => "a PDF stream is truncated",
                        _ => "the PDF object syntax is malformed",
                    }
                    .to_string(),
                ),
            );
            return report;
        }
    };
    if stream_boundaries_unverified {
        add_reason(
            &mut report,
            limits,
            ReasonKind::Unsupported,
            "pdf-streams",
            Some("PDF stream boundaries and filters are not yet decoded from /Length".to_string()),
        );
    }
    if names.contains("Encrypt") {
        add_reason(
            &mut report,
            limits,
            ReasonKind::Encrypted,
            "pdf-encryption",
            Some("encrypted PDF objects cannot be fully inspected".to_string()),
        );
    }
    if names.contains("ObjStm") {
        add_reason(
            &mut report,
            limits,
            ReasonKind::Unsupported,
            "pdf-object-stream",
            Some("compressed PDF object streams are not yet decoded".to_string()),
        );
    }
    if names.contains("JavaScript") || names.contains("JS") {
        add_pdf_feature(
            &mut report,
            limits,
            FeatureKind::PdfJavaScript,
            "PDF-JAVASCRIPT",
            "the PDF declares JavaScript",
        );
    }
    if names.contains("OpenAction") || names.contains("AA") {
        add_pdf_feature(
            &mut report,
            limits,
            FeatureKind::PdfAutomaticAction,
            "PDF-AUTOMATIC-ACTION",
            "the PDF declares an automatic action",
        );
    }
    if names.contains("Launch") {
        add_pdf_feature(
            &mut report,
            limits,
            FeatureKind::PdfLaunchAction,
            "PDF-LAUNCH-ACTION",
            "the PDF declares a launch action",
        );
    }
    if names.contains("EmbeddedFiles")
        || names.contains("EmbeddedFile")
        || names.contains("Filespec")
    {
        add_pdf_feature(
            &mut report,
            limits,
            FeatureKind::PdfEmbeddedFile,
            "PDF-EMBEDDED-FILE",
            "the PDF declares an embedded file",
        );
    }
    if names.contains("XFA") {
        add_pdf_feature(
            &mut report,
            limits,
            FeatureKind::PdfXfa,
            "PDF-XFA",
            "the PDF declares XFA content",
        );
    }
    if ["URI", "GoToR", "SubmitForm", "ImportData"]
        .iter()
        .any(|name| names.contains(*name))
    {
        add_pdf_feature(
            &mut report,
            limits,
            FeatureKind::PdfExternalReference,
            "PDF-EXTERNAL-REFERENCE",
            "the PDF declares an external reference or submission action",
        );
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazaret_archive::{EntryKind, Format};

    fn file(name: &str, data: impl AsRef<[u8]>) -> Entry {
        Entry {
            name: name.to_string(),
            kind: EntryKind::File,
            data: data.as_ref().to_vec(),
            windows_name: None,
            collision: None,
        }
    }

    fn archive(entries: Vec<Entry>) -> Archive {
        Archive {
            format: Format::Zip,
            entries,
            collisions: Vec::new(),
        }
    }

    fn package(prefix: &str, content_type: &str) -> Archive {
        let main = format!("{prefix}/document.xml");
        archive(vec![
            file(
                "[Content_Types].xml",
                format!(
                    r#"<Types><Override PartName="/{main}" ContentType="{content_type}"/></Types>"#
                ),
            ),
            file(
                "_rels/.rels",
                format!(
                    r#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="{main}"/></Relationships>"#
                ),
            ),
            file(&main, b"<main/>"),
        ])
    }

    #[test]
    fn confirms_word_and_spreadsheet_from_package_structure() {
        let pack = crate::pack::current();
        let word = package(
            "word",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        );
        let sheet = package(
            "xl",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
        );
        let word = analyze_ooxml(&word, &pack, Limits::default());
        let sheet = analyze_ooxml(&sheet, &pack, Limits::default());
        assert_eq!(word.kind, Some(DocumentKind::Wordprocessing));
        assert!(word.is_confirmed(), "{word:?}");
        assert_eq!(sheet.kind, Some(DocumentKind::Spreadsheet));
        assert!(sheet.is_confirmed(), "{sheet:?}");
    }

    #[test]
    fn a_generic_zip_is_not_an_ooxml_document() {
        let pack = crate::pack::current();
        let report = analyze_ooxml(
            &archive(vec![file("hello.txt", b"hello")]),
            &pack,
            Limits::default(),
        );
        assert_eq!(report.kind, None);
        assert!(report.reasons.is_empty());
    }

    #[test]
    fn reports_active_and_external_package_features() {
        let pack = crate::pack::current();
        let mut value = package(
            "word",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        );
        value.entries.extend([
            file("word/vbaProject.bin", b"macro"),
            file("word/activeX/activeX1.bin", b"control"),
            file("word/embeddings/item.bin", b"object"),
            file(
                "word/_rels/document.xml.rels",
                br#"<Relationships><Relationship Id="rId2" Type="image" TargetMode="External" Target="https://example.invalid/a.png"/></Relationships>"#,
            ),
        ]);
        let report = analyze_ooxml(&value, &pack, Limits::default());
        let kinds: BTreeSet<_> = report.features.iter().map(|feature| feature.kind).collect();
        assert!(kinds.contains(&FeatureKind::Macro));
        assert!(kinds.contains(&FeatureKind::ActiveX));
        assert!(kinds.contains(&FeatureKind::EmbeddedObject));
        assert!(kinds.contains(&FeatureKind::ExternalRelationship));
    }

    #[test]
    fn review3_main_part_typed_by_default_extension_still_inspected() {
        let pack = crate::pack::current();
        let value = archive(vec![
            file(
                "[Content_Types].xml",
                br#"<Types><Default Extension="xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#,
            ),
            file(
                "_rels/.rels",
                br#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#,
            ),
            file("word/document.xml", b"<main/>"),
            file("word/activeX/control.bin", b"control"),
        ]);

        let report = analyze_ooxml(&value, &pack, Limits::default());
        assert_eq!(
            report.kind,
            Some(DocumentKind::Wordprocessing),
            "{report:?}"
        );
        assert!(
            report
                .features
                .iter()
                .any(|feature| feature.id == "OOXML-ACTIVEX"),
            "{report:?}"
        );
    }

    #[test]
    fn review3_two_main_relationships_still_inspected() {
        let pack = crate::pack::current();
        let mut value = package(
            "word",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        );
        let relationships = value
            .entries
            .iter_mut()
            .find(|entry| entry.name == "_rels/.rels")
            .expect("root relationships");
        relationships.data = br#"<Relationships>
            <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
            <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/other.xml"/>
        </Relationships>"#
            .to_vec();
        value
            .entries
            .push(file("word/embeddings/program.bin", b"MZ\x90\x00\x03\x00"));

        let report = analyze_ooxml(&value, &pack, Limits::default());
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| reason.kind == ReasonKind::Ambiguous),
            "{report:?}"
        );
        assert!(
            report
                .features
                .iter()
                .any(|feature| feature.id == "OOXML-EMBEDDED-OBJECT"),
            "{report:?}"
        );
    }

    #[test]
    fn vba_typed_by_default_extension_is_detected() {
        let pack = crate::pack::current();
        let mut value = package(
            "word",
            "application/vnd.ms-word.document.macroEnabled.main+xml",
        );
        let content_types = value
            .entries
            .iter_mut()
            .find(|entry| entry.name == "[Content_Types].xml")
            .expect("content types");
        let xml = String::from_utf8(content_types.data.clone()).expect("content types XML");
        content_types.data = xml
            .replace(
                "</Types>",
                r#"<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>"#,
            )
            .into_bytes();
        value
            .entries
            .push(file("word/unexpected-name.bin", b"macro"));

        let report = analyze_ooxml(&value, &pack, Limits::default());
        assert!(
            report
                .features
                .iter()
                .any(|feature| feature.id == "OOXML-MACRO"),
            "{report:?}"
        );
    }

    #[test]
    fn namespace_declarations_cannot_hide_relationship_attributes() {
        let pack = crate::pack::current();
        let mut value = package(
            "word",
            "application/vnd.ms-word.document.macroEnabled.main+xml",
        );
        value.entries.push(file(
            "word/_rels/document.xml.rels",
            br#"<Relationships>
                <Relationship Id="rIdExternal" xmlns:TargetMode="urn:decoy" Type="image" TargetMode="External" Target="https://example.invalid/a.png"/>
                <Relationship Id="rIdVba" xmlns:Type="urn:decoy" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="renamed.bin"/>
            </Relationships>"#,
        ));

        let report = analyze_ooxml(&value, &pack, Limits::default());
        assert!(
            report
                .features
                .iter()
                .any(|feature| feature.id == "OOXML-EXTERNAL-RELATIONSHIP"),
            "{report:?}"
        );
        assert!(
            report
                .features
                .iter()
                .any(|feature| feature.id == "OOXML-MACRO"),
            "{report:?}"
        );
    }

    #[test]
    fn duplicate_xml_attributes_are_malformed() {
        assert!(matches!(
            xml_tags(
                br#"<Relationships><Relationship Id="one" Id="two"/></Relationships>"#,
                Limits::default(),
            ),
            Err(ReasonKind::Malformed)
        ));
    }

    #[test]
    fn macro_enabled_office_main_parts_are_inspected() {
        let pack = crate::pack::current();
        let cases = [
            (
                "word",
                "application/vnd.ms-word.document.macroEnabled.main+xml",
                DocumentKind::Wordprocessing,
            ),
            (
                "xl",
                "application/vnd.ms-excel.sheet.macroEnabled.main+xml",
                DocumentKind::Spreadsheet,
            ),
            (
                "ppt",
                "application/vnd.ms-powerpoint.presentation.macroEnabled.main+xml",
                DocumentKind::Presentation,
            ),
            (
                "word",
                "application/vnd.ms-word.template.macroEnabledTemplate.main+xml",
                DocumentKind::Wordprocessing,
            ),
            (
                "xl",
                "application/vnd.ms-excel.template.macroEnabled.main+xml",
                DocumentKind::Spreadsheet,
            ),
            (
                "ppt",
                "application/vnd.ms-powerpoint.template.macroEnabled.main+xml",
                DocumentKind::Presentation,
            ),
            (
                "xl",
                "application/vnd.ms-excel.addin.macroEnabled.main+xml",
                DocumentKind::Spreadsheet,
            ),
        ];
        for (prefix, content_type, kind) in cases {
            let mut value = package(prefix, content_type);
            value
                .entries
                .push(file(&format!("{prefix}/vbaProject.bin"), b"macro"));
            let report = analyze_ooxml(&value, &pack, Limits::default());
            assert_eq!(report.kind, Some(kind), "{content_type}: {report:?}");
            assert!(
                report
                    .features
                    .iter()
                    .any(|feature| feature.id == "OOXML-MACRO"),
                "{content_type}: {report:?}"
            );
        }
    }

    #[test]
    fn a_renamed_vba_project_is_found_by_content_type_or_relationship() {
        let pack = crate::pack::current();
        let mut by_content_type = package(
            "word",
            "application/vnd.ms-word.document.macroEnabled.main+xml",
        );
        let content_types = by_content_type
            .entries
            .iter_mut()
            .find(|entry| entry.name == "[Content_Types].xml")
            .expect("content types");
        let xml = String::from_utf8(content_types.data.clone()).expect("content types XML");
        content_types.data = xml.replace(
            "</Types>",
            r#"<Override PartName="/word/renamed.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>"#,
        ).into_bytes();
        by_content_type
            .entries
            .push(file("word/renamed.bin", b"macro"));

        let mut by_relationship = package(
            "word",
            "application/vnd.ms-word.document.macroEnabled.main+xml",
        );
        by_relationship.entries.extend([
            file("word/other-name.bin", b"macro"),
            file(
                "word/_rels/document.xml.rels",
                br#"<Relationships><Relationship Id="rIdVba" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="other-name.bin"/></Relationships>"#,
            ),
        ]);

        for value in [&by_content_type, &by_relationship] {
            let report = analyze_ooxml(value, &pack, Limits::default());
            assert!(
                report
                    .features
                    .iter()
                    .any(|feature| feature.id == "OOXML-MACRO"),
                "{report:?}"
            );
        }
    }

    #[test]
    fn active_features_survive_an_unrecognized_main_part_type() {
        let pack = crate::pack::current();
        let mut value = package("word", "application/vnd.example.unknown.main+xml");
        value.entries.extend([
            file("word/vbaProject.bin", b"macro"),
            file("word/activeX/activeX1.bin", b"control"),
            // An undeclared, innocently named member is still inspected by bytes.
            file(
                "word/media/preview.dat",
                b"MZ\x90\x00\x03\x00\x00\x00\x04\x00",
            ),
        ]);
        let report = analyze_ooxml(&value, &pack, Limits::default());
        assert_eq!(report.kind, None, "{report:?}");
        assert!(report
            .reasons
            .iter()
            .any(|reason| reason.kind == ReasonKind::Unsupported));
        for id in ["OOXML-MACRO", "OOXML-ACTIVEX", "OOXML-EMBEDDED-PROGRAM"] {
            assert!(
                report.features.iter().any(|feature| feature.id == id),
                "{id}: {report:?}"
            );
        }
    }

    #[test]
    fn missing_or_cross_family_main_parts_are_not_confirmed() {
        let pack = crate::pack::current();
        let mut missing = package(
            "word",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        );
        missing.entries.pop();
        let crossed = package(
            "xl",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        );
        let missing = analyze_ooxml(&missing, &pack, Limits::default());
        let crossed = analyze_ooxml(&crossed, &pack, Limits::default());
        assert!(!missing.is_confirmed(), "{missing:?}");
        assert!(!crossed.is_confirmed(), "{crossed:?}");
    }

    fn pdf(catalog: &str, suffix: &str) -> Vec<u8> {
        let mut value =
            format!("%PDF-1.7\n1 0 obj\n<< /Type /Catalog {catalog} >>\nendobj\n").into_bytes();
        let xref = value.len();
        value.extend_from_slice(
            format!(
                "xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Root 1 0 R /Size 2 >>\nstartxref\n{xref}\n%%EOF{suffix}"
            )
            .as_bytes(),
        );
        value
    }

    #[test]
    fn confirms_a_structural_pdf_and_ignores_names_in_page_streams() {
        let mut value = pdf("", "");
        let xref = value
            .windows(b"xref".len())
            .position(|part| part == b"xref")
            .expect("xref");
        value.splice(
            xref..xref,
            b"2 0 obj\n<< /Length 18 >>\nstream\n/JavaScript /Launch\nendstream\nendobj\n"
                .iter()
                .copied(),
        );
        let new_xref = value
            .windows(b"xref".len())
            .position(|part| part == b"xref")
            .expect("xref");
        let startxref = value
            .windows(b"startxref".len())
            .position(|part| part == b"startxref")
            .expect("startxref")
            + b"startxref\n".len();
        let end = startxref
            + value[startxref..]
                .iter()
                .position(|byte| *byte == b'\n')
                .expect("offset line");
        value.splice(startxref..end, new_xref.to_string().bytes());
        let report = analyze_pdf(&value, Limits::default());
        assert_eq!(report.kind, Some(DocumentKind::Pdf));
        assert!(report.is_confirmed(), "{report:?}");
        assert!(!report.is_complete(), "{report:?}");
        assert!(report.features.is_empty(), "{report:?}");
    }

    #[test]
    fn reports_active_pdf_capabilities() {
        let report = analyze_pdf(
            &pdf(
                "/OpenAction << /S /JavaScript /JS (x) >> /AA <<>> /Launch <<>> /Names << /EmbeddedFiles <<>> >> /AcroForm << /XFA 2 0 R >> /URI (https://example.invalid)",
                "",
            ),
            Limits::default(),
        );
        let kinds: BTreeSet<_> = report.features.iter().map(|feature| feature.kind).collect();
        assert!(kinds.contains(&FeatureKind::PdfJavaScript));
        assert!(kinds.contains(&FeatureKind::PdfAutomaticAction));
        assert!(kinds.contains(&FeatureKind::PdfLaunchAction));
        assert!(kinds.contains(&FeatureKind::PdfEmbeddedFile));
        assert!(kinds.contains(&FeatureKind::PdfXfa));
        assert!(kinds.contains(&FeatureKind::PdfExternalReference));
    }

    #[test]
    fn encrypted_and_object_stream_pdfs_are_incomplete() {
        let report = analyze_pdf(&pdf("/Encrypt 2 0 R /Type /ObjStm", ""), Limits::default());
        assert!(report.is_confirmed(), "{report:?}");
        assert!(!report.is_complete(), "{report:?}");
        assert!(report
            .reasons
            .iter()
            .any(|reason| reason.kind == ReasonKind::Encrypted));
        assert!(report
            .reasons
            .iter()
            .any(|reason| reason.kind == ReasonKind::Unsupported));
    }

    #[test]
    fn rejects_truncated_or_misdirected_pdfs() {
        let truncated = analyze_pdf(b"%PDF-1.7\n1 0 obj\n<<>>\n", Limits::default());
        let mut bad_xref = pdf("", "");
        let startxref = bad_xref
            .windows(b"startxref".len())
            .position(|part| part == b"startxref")
            .expect("startxref")
            + b"startxref\n".len();
        let end = startxref
            + bad_xref[startxref..]
                .iter()
                .position(|byte| *byte == b'\n')
                .expect("offset line");
        bad_xref.splice(startxref..end, b"1".iter().copied());
        let bad_xref = analyze_pdf(&bad_xref, Limits::default());
        assert!(!truncated.is_confirmed(), "{truncated:?}");
        assert!(!bad_xref.is_confirmed(), "{bad_xref:?}");
    }

    #[test]
    fn reports_trailing_bytes_and_incremental_revisions() {
        let mut value = pdf("", "\ntrailer-data");
        let old = pdf("", "\n");
        value.splice(9..9, old.into_iter());
        let report = analyze_pdf(&value, Limits::default());
        let kinds: BTreeSet<_> = report.features.iter().map(|feature| feature.kind).collect();
        assert!(kinds.contains(&FeatureKind::TrailingData));
        assert!(kinds.contains(&FeatureKind::IncrementalRevision));
    }

    #[test]
    fn malformed_ooxml_metadata_is_not_confirmed() {
        let pack = crate::pack::current();
        let value = archive(vec![
            file(
                "[Content_Types].xml",
                br#"<Types><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"></Types>"#,
            ),
            file(
                "_rels/.rels",
                br#"<Relationships><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#,
            ),
            file("word/document.xml", b"<document/>"),
            file("word/activeX/control.bin", b"control"),
        ]);
        let report = analyze_ooxml(&value, &pack, Limits::default());
        assert!(!report.is_confirmed(), "{report:?}");
        assert!(report
            .reasons
            .iter()
            .any(|reason| reason.kind == ReasonKind::Malformed));
        assert!(
            report
                .features
                .iter()
                .any(|feature| feature.id == "OOXML-ACTIVEX"),
            "{report:?}"
        );
    }
}
