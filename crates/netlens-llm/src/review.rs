//! One model call for `netlens review`: build the prompt, call the backend,
//! audit the call, validate citations, unmask IPs.

use crate::cite::{validate, Claim, Dropped};
use crate::client::{ChatBackend, LlmError, ModelConfig};
use crate::prompt::{build_messages, prompt_text, ReviewContext};
use netlens_core::audit::AuditLog;
use netlens_core::ipmask::IpMasker;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct LlmReview {
    pub model: String,
    pub endpoint: String,
    pub latency_ms: u128,
    pub prompt_bytes: usize,
    pub prompt_sha256: String,
    pub claims: Vec<Claim>,
    pub dropped: Vec<Dropped>,
    pub unknown_ids: Vec<String>,
}

impl LlmReview {
    pub fn section(&self, name: &str) -> Vec<&Claim> {
        self.claims.iter().filter(|c| c.section == name).collect()
    }
}

pub fn run_review(
    backend: &dyn ChatBackend,
    cfg: &ModelConfig,
    ctx: &ReviewContext,
    masker: Option<&IpMasker>,
    audit: &AuditLog,
    store_prompt: bool,
) -> Result<LlmReview, LlmError> {
    let messages = build_messages(ctx);
    let ptext = prompt_text(&messages);
    let endpoint = backend.describe();
    let result = backend.chat(&messages);
    let (resp_len, latency, err) = match &result {
        Ok(c) => (c.raw_len, c.latency_ms, None),
        Err(e) => (0, 0, Some(e.to_string())),
    };
    // Audit failures must not be silent, but must not hide the model result either.
    if let Err(e) = audit.model_call(
        &cfg.model,
        &endpoint,
        &ptext,
        resp_len,
        latency,
        err.is_none(),
        err.as_deref(),
        store_prompt,
    ) {
        eprintln!("warning: could not write audit log: {e}");
    }
    let c = result?;
    let mut v = validate(&c.text, &ctx.ids());
    if let Some(m) = masker {
        for cl in v.claims.iter_mut() {
            cl.text = m.unmask(&cl.text);
        }
        for d in v.dropped.iter_mut() {
            d.text = m.unmask(&d.text);
        }
    }
    Ok(LlmReview {
        model: c.model,
        endpoint,
        latency_ms: c.latency_ms,
        prompt_bytes: ptext.len(),
        prompt_sha256: netlens_core::sha256_hex(ptext.as_bytes()),
        claims: v.claims,
        dropped: v.dropped,
        unknown_ids: v.unknown_ids,
    })
}
