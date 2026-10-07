//! netlens-llm: talk to any OpenAI-compatible endpoint (Ollama, LM Studio,
//! llama.cpp server, mlx-lm), strip Qwen3 `<think>` blocks, build the review
//! prompt from redacted evidence, and validate that every claim cites it.

pub mod cite;
pub mod client;
pub mod mock;
pub mod prompt;
pub mod review;
pub mod think;

pub use cite::{validate, Claim, Dropped, Validated};
pub use client::{backend_for, ChatBackend, ChatMessage, Completion, LlmError, ModelConfig};
pub use review::{run_review, LlmReview};

/// Default endpoint (Ollama's OpenAI-compatible API).
pub const DEFAULT_MODEL_URL: &str = "http://localhost:11434/v1";
/// Default model: Qwen3-14B, 4-bit (Ollama tag `qwen3:14b`), fits a 24 GB Mac.
pub const DEFAULT_MODEL: &str = "qwen3:14b";
