# Models

netlens talks to any **OpenAI-compatible** `/v1/chat/completions` endpoint: Ollama,
LM Studio, llama.cpp `llama-server`, vLLM, or a hosted API. The model writes only the
prose (risk summary, blast radius, rollback explanation). Findings and the rollback
itself are always deterministic.

## Recommended local setup (24 GB Apple Silicon)

```sh
ollama pull qwen3:14b                 # default: Qwen3-14B, 4-bit (~9 GB)
OLLAMA_CONTEXT_LENGTH=16384 ollama serve
netlens review before.cfg after.cfg   # uses http://localhost:11434/v1 + qwen3:14b
```

| Model | Ollama tag | Memory | Notes |
|---|---|---|---|
| Qwen3-14B 4-bit | `qwen3:14b` | ~9-10 GB | Default. Fast, follows the citation format well. |
| Qwen3.6-27B 4-bit | `qwen3.6:27b` | ~18-19 GB | Stronger reasoning; tight on 24 GB, comfortable on 32 GB+. |

Prompts are usually 2-8k tokens. Ollama's default context window can be smaller,
in which case it silently truncates the prompt. Raise it with
`OLLAMA_CONTEXT_LENGTH` (or a Modelfile `PARAMETER num_ctx 16384`).

## Runtimes

Any server that speaks the OpenAI chat-completions API works. Point `--model-url`
at its `/v1` base URL.

| Runtime | Link | Typical base URL | Example |
|---|---|---|---|
| Ollama | <https://ollama.com> | `http://localhost:11434/v1` (default) | `ollama pull qwen3:14b` |
| LM Studio | <https://lmstudio.ai> | `http://localhost:1234/v1` | load a Qwen3-14B GGUF/MLX build, start the local server |
| llama.cpp | <https://github.com/ggml-org/llama.cpp> | `http://localhost:8080/v1` | `llama-server -hf Qwen/Qwen3-14B-GGUF:Q4_K_M -c 16384` |
| mlx-lm (Apple Silicon) | <https://github.com/ml-explore/mlx-lm> | `http://localhost:8080/v1` | `mlx_lm.server --model mlx-community/Qwen3-14B-4bit` |

```sh
netlens review before.cfg after.cfg --model-url http://localhost:1234/v1 --model qwen3-14b
```

The model name must be whatever the server expects (`ollama list`, LM Studio's model
id, or anything for single-model servers like `llama-server`).

## Thinking

netlens doesn't need chain-of-thought, and thinking makes reviews slower. By default it:

- sends `reasoning_effort: "none"` for Qwen models (Ollama/vLLM support it). If a
  server rejects the field, netlens retries once without it;
- appends Qwen3's `/no_think` soft switch to the prompt (Qwen3.6 ignores it; the
  field above covers that model);
- **always** strips `<think>...</think>` blocks from the answer, including
  unterminated ones.

Use `--think` (or `think = true` in the config) to let the model think anyway.

## Citations are enforced

The system prompt requires every bullet to end with evidence ids: `[F1]` rule
findings, `[B1]` Batfish findings, `[C1]` raw changes, `[R1]` the rollback. netlens
then validates the answer:

- a bullet with no valid id is **dropped**;
- unknown ids (`[F99]`) are removed. If nothing valid is left, the bullet is dropped;
- the report shows how many claims were dropped, and `--keep-uncited` lists them as
  `UNVERIFIED`. `--json` always includes them under `llm.dropped`.

## Settings

| Flag | Env | Config key | Default |
|---|---|---|---|
| `--model-url` | `NETLENS_MODEL_URL` | `model_url` | `http://localhost:11434/v1` |
| `--model` | `NETLENS_MODEL` | `model` | `qwen3:14b` |
| - | `NETLENS_API_KEY` | `api_key` | none (sent as `Authorization: Bearer`) |
| `--timeout` | - | `timeout_secs` | 300 |
| `--think` | - | `think` | false |
| `--no-llm` | - | - | model enabled |

If the model is unreachable, `review` prints a warning and still shows the full
deterministic report (exit code unchanged).

## Mock model (tests, CI, demos)

- `--model-url mock://` uses an in-process deterministic model.
- `cargo run -p netlens-mock -- llm --port 11435` starts an HTTP server; then pass
  `--model-url http://127.0.0.1:11435/v1`.

The mock answers from the evidence list. It also deliberately includes one uncited
claim and one claim citing `[F99]`, so the validator is visible in demos.
