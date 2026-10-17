//! CI files read for what they run (0.1.9; BR-7 step 1 moved them here from the packages' twins:
//! scanner/ghworkflow.py and gitlabci.py, js/src/lib/ghworkflow.js and gitlabci.js). GitHub Actions workflows
//! (workflow.rs: SC-WORKFLOW-*) and GitLab CI files (gitlab.rs: SC-GITLAB-*), both read on the YAML's outline
//! (outline.rs). Both packages ask the engine (`ci_*` calls, api.rs) and shape the issues it answers.

pub mod exfil;
pub mod gitlab;
pub mod outline;
pub mod workflow;

use crate::findings::RuleText;
use crate::json::Value;
use crate::pack::Pack;

/// Which CI file `path` is: "workflow", "gitlab", or None.
pub fn kind_of(path: &[u32]) -> Option<&'static str> {
    if workflow::is_workflow(path) {
        Some("workflow")
    } else if gitlab::is_gitlab_ci(path) {
        Some("gitlab")
    } else {
        None
    }
}

/// A workflow's findings, in the order its issues are made: the worms' shapes (every secret handed out), the
/// secrets sent out by name and the credential sweeps (RA-1, exfil.rs), then the backdoor.
pub fn workflow_findings(p: &Pack, text: &[u32]) -> Vec<workflow::Found> {
    let mut out = workflow::findings(p, text);
    out.extend(exfil::exfil(p, text));
    out.extend(workflow::backdoor(p, text));
    out
}

/// The rule of a workflow's finding (workflow.rs's kinds, exfil.rs's).
fn workflow_rule(p: &Pack, kind: &str, d: &Value) -> Option<RuleText> {
    workflow::rule(p, kind, d).or_else(|| exfil::rule(p, kind, d))
}

/// The rule of a finding of the `ci` reader ("workflow" or "gitlab").
pub fn rule(p: &Pack, ci: &str, kind: &str, d: &Value) -> Option<RuleText> {
    match ci {
        "workflow" => workflow_rule(p, kind, d),
        "gitlab" => gitlab::rule(p, kind, d),
        _ => None,
    }
}

/// The issues of a CI file at `path` (core.workflow_issues / gitlab_issues): [(line, rule)] in their order — a
/// workflow's findings, then its hardening checks; a GitLab file's checks. Nothing for another file.
pub fn issues(p: &Pack, path: &[u32], text: &[u32]) -> Vec<(usize, RuleText)> {
    let mut out = Vec::new();
    match kind_of(path) {
        Some("workflow") => {
            for (kind, line, d) in workflow_findings(p, text).into_iter().chain(workflow::hardening(p, text)) {
                if let Some(r) = workflow_rule(p, kind, &d) {
                    out.push((line, r));
                }
            }
        }
        Some("gitlab") => {
            for (kind, line, d) in gitlab::hardening(p, text) {
                if let Some(r) = gitlab::rule(p, kind, &d) {
                    out.push((line, r));
                }
            }
        }
        _ => {}
    }
    out
}

/// A finding as the calls answer it: [kind, line, detail].
pub fn found_value(f: &workflow::Found) -> Value {
    Value::Arr(vec![Value::str(f.0), Value::Int(f.1 as i64), f.2.clone()])
}

/// A rule as the calls answer it: {id, name, type, sev, msg, why, fix, ref}.
pub fn rule_value(r: &RuleText) -> Value {
    Value::obj(vec![
        ("id", Value::Str(r.id.clone())),
        ("name", Value::Str(r.name.clone())),
        ("type", Value::Str(r.typ.clone())),
        ("sev", Value::Str(r.sev.clone())),
        ("msg", Value::Str(r.msg.clone())),
        ("why", Value::Str(r.why.clone())),
        ("fix", Value::Str(r.fix.clone())),
        ("ref", Value::Str(r.ref_.clone())),
    ])
}
