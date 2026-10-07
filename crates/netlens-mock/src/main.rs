//! `netlens-mock llm|batfish [--port N] [--host H]`: run a mock server in the foreground.

fn usage() -> ! {
    eprintln!("usage: netlens-mock <llm|batfish> [--host 127.0.0.1] [--port N]\n  llm      OpenAI-compatible mock model (default port 11435); use --model-url http://127.0.0.1:11435/v1\n  batfish  mock Batfish v2 coordinator (default port 9996); use --batfish http://127.0.0.1:9996");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(kind) = args.first().cloned() else {
        usage()
    };
    let mut host = "127.0.0.1".to_string();
    let mut port: Option<u16> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                port = args
                    .get(i + 1)
                    .and_then(|p| p.parse().ok())
                    .or_else(|| usage())
            }
            "--host" => host = args.get(i + 1).cloned().unwrap_or_else(|| usage()),
            "-h" | "--help" => usage(),
            _ => usage(),
        }
        i += 2;
    }
    let res = match kind.as_str() {
        "llm" => netlens_mock::spawn_llm(&format!("{host}:{}", port.unwrap_or(11435)))
            .map(|s| (s, "/v1")),
        "batfish" => netlens_mock::spawn_batfish(&format!("{host}:{}", port.unwrap_or(9996)))
            .map(|s| (s, "")),
        _ => usage(),
    };
    match res {
        Ok((s, suffix)) => {
            eprintln!(
                "netlens-mock {kind} listening on {}{suffix} (Ctrl-C to stop)",
                s.url
            );
            loop {
                std::thread::park();
            }
        }
        Err(e) => {
            eprintln!("error: cannot start mock server: {e}");
            std::process::exit(1);
        }
    }
}
