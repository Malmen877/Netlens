//! Minimal OpenAI-compatible chat client plus an in-process mock backend.

use crate::think::strip_think;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

impl ChatMessage {
    pub fn system(c: impl Into<String>) -> Self {
        ChatMessage {
            role: "system".into(),
            content: c.into(),
        }
    }
    pub fn user(c: impl Into<String>) -> Self {
        ChatMessage {
            role: "user".into(),
            content: c.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ModelConfig {
    /// Base URL, e.g. http://localhost:11434/v1, or `mock://` for the built-in mock.
    pub url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub timeout: Duration,
    pub temperature: f32,
    pub max_tokens: Option<u32>,
    /// Ask Qwen3 to skip its reasoning phase (`/no_think`); faster, and
    /// `<think>` output is stripped either way.
    pub no_think: bool,
}

impl Default for ModelConfig {
    fn default() -> Self {
        ModelConfig {
            url: crate::DEFAULT_MODEL_URL.into(),
            model: crate::DEFAULT_MODEL.into(),
            api_key: None,
            timeout: Duration::from_secs(300),
            temperature: 0.1,
            max_tokens: Some(1200),
            no_think: true,
        }
    }
}

impl ModelConfig {
    pub fn is_mock(&self) -> bool {
        self.url.starts_with("mock://") || self.url == "mock"
    }

    /// The chat-completions endpoint for this base URL.
    pub fn endpoint(&self) -> String {
        chat_endpoint(&self.url)
    }
}

/// `http://host:11434` -> `http://host:11434/v1/chat/completions`;
/// `.../v1` -> `.../v1/chat/completions`; a full endpoint is kept.
pub fn chat_endpoint(url: &str) -> String {
    let u = url.trim_end_matches('/');
    if u.ends_with("/chat/completions") {
        return u.to_string();
    }
    let after_scheme = u.split_once("://").map(|(_, r)| r).unwrap_or(u);
    if !after_scheme.contains('/') {
        return format!("{u}/v1/chat/completions");
    }
    format!("{u}/chat/completions")
}

#[derive(Debug, Clone)]
pub struct Completion {
    /// Answer text with `<think>` blocks removed.
    pub text: String,
    pub raw_len: usize,
    pub latency_ms: u128,
    pub model: String,
}

#[derive(Debug, Error)]
pub enum LlmError {
    #[error("cannot reach the model at {endpoint}: {detail}. Is the server running (e.g. `ollama serve`)? Use --no-llm to skip the model, or --model-url to point elsewhere.")]
    Unreachable { endpoint: String, detail: String },
    #[error("model server returned HTTP {status}: {body}{hint}")]
    Http {
        status: u16,
        body: String,
        hint: String,
    },
    #[error("model server sent an unexpected response: {0}")]
    BadResponse(String),
    #[error("model call timed out after {0:?}; try a smaller model or raise --timeout")]
    Timeout(Duration),
}

pub trait ChatBackend {
    fn chat(&self, messages: &[ChatMessage]) -> Result<Completion, LlmError>;
    fn describe(&self) -> String;
}

pub fn backend_for(cfg: &ModelConfig) -> Box<dyn ChatBackend> {
    if cfg.is_mock() {
        Box::new(MockBackend {
            model: cfg.model.clone(),
        })
    } else {
        Box::new(OpenAiClient::new(cfg.clone()))
    }
}

pub struct OpenAiClient {
    cfg: ModelConfig,
    agent: ureq::Agent,
}

impl OpenAiClient {
    pub fn new(cfg: ModelConfig) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout(cfg.timeout)
            .build();
        OpenAiClient { cfg, agent }
    }
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage>,
    temperature: f32,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
    #[serde(default)]
    model: Option<String>,
}

#[derive(Deserialize)]
struct Choice {
    message: RespMessage,
}

#[derive(Deserialize)]
struct RespMessage {
    #[serde(default)]
    content: Option<String>,
}

/// Add Qwen3's `/no_think` soft switch to the last user message.
pub fn apply_no_think(model: &str, messages: &[ChatMessage], no_think: bool) -> Vec<ChatMessage> {
    let mut m = messages.to_vec();
    if no_think && model.to_ascii_lowercase().contains("qwen3") {
        if let Some(last) = m.iter_mut().rev().find(|x| x.role == "user") {
            if !last.content.contains("/no_think") {
                last.content.push_str("\n/no_think");
            }
        }
    }
    m
}

impl ChatBackend for OpenAiClient {
    fn describe(&self) -> String {
        self.cfg.endpoint()
    }

    fn chat(&self, messages: &[ChatMessage]) -> Result<Completion, LlmError> {
        let endpoint = self.cfg.endpoint();
        let body = ChatRequest {
            model: &self.cfg.model,
            messages: apply_no_think(&self.cfg.model, messages, self.cfg.no_think),
            temperature: self.cfg.temperature,
            stream: false,
            max_tokens: self.cfg.max_tokens,
        };
        let mut req = self
            .agent
            .post(&endpoint)
            .set("Content-Type", "application/json");
        if let Some(k) = self.cfg.api_key.as_deref().filter(|k| !k.is_empty()) {
            req = req.set("Authorization", &format!("Bearer {k}"));
        }
        let start = Instant::now();
        let resp = match req.send_json(
            serde_json::to_value(&body).map_err(|e| LlmError::BadResponse(e.to_string()))?,
        ) {
            Ok(r) => r,
            Err(ureq::Error::Status(status, r)) => {
                let text = r.into_string().unwrap_or_default();
                let body: String = text.chars().take(400).collect();
                let hint = if status == 404 && body.contains("not found") {
                    format!(" (hint: `ollama pull {}` or pass --model)", self.cfg.model)
                } else if status == 401 || status == 403 {
                    " (hint: set NETLENS_API_KEY)".to_string()
                } else {
                    String::new()
                };
                return Err(LlmError::Http { status, body, hint });
            }
            Err(ureq::Error::Transport(t)) => {
                let detail = t.to_string();
                if detail.to_ascii_lowercase().contains("timed out") {
                    return Err(LlmError::Timeout(self.cfg.timeout));
                }
                return Err(LlmError::Unreachable { endpoint, detail });
            }
        };
        let raw = resp
            .into_string()
            .map_err(|e| LlmError::BadResponse(e.to_string()))?;
        let latency_ms = start.elapsed().as_millis();
        let parsed: ChatResponse = serde_json::from_str(&raw).map_err(|e| {
            LlmError::BadResponse(format!(
                "{e}: {}",
                raw.chars().take(200).collect::<String>()
            ))
        })?;
        let content = parsed
            .choices
            .into_iter()
            .next()
            .and_then(|c| c.message.content)
            .ok_or_else(|| LlmError::BadResponse("no choices[0].message.content".into()))?;
        Ok(Completion {
            raw_len: content.len(),
            text: strip_think(&content),
            latency_ms,
            model: parsed.model.unwrap_or_else(|| self.cfg.model.clone()),
        })
    }
}

/// In-process mock (`--model-url mock://`): deterministic, properly cited
/// answers built from the evidence in the prompt.
pub struct MockBackend {
    pub model: String,
}

impl ChatBackend for MockBackend {
    fn describe(&self) -> String {
        "mock://".into()
    }

    fn chat(&self, messages: &[ChatMessage]) -> Result<Completion, LlmError> {
        let start = Instant::now();
        let raw = crate::mock::respond(messages);
        Ok(Completion {
            raw_len: raw.len(),
            text: strip_think(&raw),
            latency_ms: start.elapsed().as_millis(),
            model: format!("mock ({})", self.model),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        assert_eq!(
            chat_endpoint("http://localhost:11434/v1"),
            "http://localhost:11434/v1/chat/completions"
        );
        assert_eq!(
            chat_endpoint("http://localhost:11434"),
            "http://localhost:11434/v1/chat/completions"
        );
        assert_eq!(
            chat_endpoint("http://localhost:1234/v1/"),
            "http://localhost:1234/v1/chat/completions"
        );
        assert_eq!(
            chat_endpoint("http://x:8080/v1/chat/completions"),
            "http://x:8080/v1/chat/completions"
        );
    }

    #[test]
    fn no_think_only_for_qwen3() {
        let m = vec![ChatMessage::system("s"), ChatMessage::user("u")];
        assert!(apply_no_think("qwen3:14b", &m, true)[1]
            .content
            .ends_with("/no_think"));
        assert_eq!(apply_no_think("llama3.1:8b", &m, true)[1].content, "u");
        assert_eq!(apply_no_think("qwen3:14b", &m, false)[1].content, "u");
    }

    #[test]
    fn unreachable_error_is_helpful() {
        let cfg = ModelConfig {
            url: "http://127.0.0.1:9/v1".into(),
            timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let err = OpenAiClient::new(cfg)
            .chat(&[ChatMessage::user("hi")])
            .unwrap_err();
        let s = err.to_string();
        assert!(s.contains("--no-llm"), "{s}");
    }
}
