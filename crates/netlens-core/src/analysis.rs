//! High-level entry points used by the CLI and the MCP server.

use crate::diff::{diff, Diff};
use crate::facts::extract;
use crate::finding::{assign_ids, Finding};
use crate::model::Config;
use crate::parse::parse;
use crate::rollback::{generate, Rollback};
use crate::rules::{self, Ctx};
use crate::unidiff::{parse_unified, to_configs};
use crate::vendor::{detect, Detection, Vendor};

pub enum Input<'a> {
    Files { before: &'a str, after: &'a str },
    Diff(&'a str),
}

#[derive(Debug, Clone)]
pub struct Analysis {
    pub vendor: Vendor,
    /// Present when the vendor was autodetected.
    pub detection: Option<Detection>,
    pub before: Config,
    pub after: Config,
    pub diff: Diff,
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
    pub rollback: Rollback,
    pub partial: bool,
}

pub fn analyze(input: &Input, vendor: Option<Vendor>) -> Result<Analysis, String> {
    let (before, after, detection, partial) = match input {
        Input::Files { before, after } => {
            let (v, det) = match vendor {
                Some(v) => (v, None),
                None => {
                    let d = detect(after);
                    let d = if d.confident {
                        d
                    } else {
                        let db = detect(before);
                        if db.confident {
                            db
                        } else {
                            d
                        }
                    };
                    (d.vendor, Some(d))
                }
            };
            (parse(before, v), parse(after, v), det, false)
        }
        Input::Diff(text) => {
            let ud = parse_unified(text)?;
            let (v, det) = match vendor {
                Some(v) => (v, None),
                None => {
                    let d = detect(&ud.after_text());
                    (d.vendor, Some(d))
                }
            };
            let (b, a) = to_configs(&ud, v);
            (b, a, det, true)
        }
    };
    let vendor = after.vendor;
    let d = diff(&before, &after);
    let (bf, af) = (extract(&before), extract(&after));
    let ctx = Ctx {
        vendor,
        before_cfg: &before,
        after_cfg: &after,
        before: &bf,
        after: &af,
        diff: &d,
        partial,
    };
    let (mut findings, notes) = rules::run(&ctx);
    assign_ids(&mut findings, "F");
    let mut rollback = generate(&before, &after);
    if partial {
        rollback
            .notes
            .push("generated from diff hunks; verify against the full running config".into());
    }
    Ok(Analysis {
        vendor,
        detection,
        before,
        after,
        diff: d,
        findings,
        notes,
        rollback,
        partial,
    })
}

/// Lint one configuration on its own.
pub fn analyze_single(
    text: &str,
    vendor: Option<Vendor>,
) -> (Config, Option<Detection>, Vec<Finding>) {
    let (v, det) = match vendor {
        Some(v) => (v, None),
        None => {
            let d = detect(text);
            (d.vendor, Some(d))
        }
    };
    let cfg = parse(text, v);
    let facts = extract(&cfg);
    let mut f = rules::lint_single(&cfg, &facts);
    assign_ids(&mut f, "F");
    (cfg, det, f)
}
