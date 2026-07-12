use axum::Json;
use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::Arc;
use zeroclaw_embedding_sidecar::reference::{DIMENSIONS, MODEL_ID, feature_hash};
use zeroclaw_embedding_sidecar::{LAUNCH_TOKEN_HEX_LEN, READINESS_PROTOCOL_VERSION};

const MAX_BATCH: usize = 128;
const MAX_INPUT_BYTES: usize = 8 * 1024;

#[derive(Clone)]
struct AppState {
    token: Arc<str>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Input {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct EmbeddingRequest {
    model: String,
    input: Input,
    encoding_format: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let token = read_launch_token()?;
    monitor_parent_control_pipe();
    if let Some(milliseconds) = fixture_readiness_delay(&args)? {
        std::thread::sleep(std::time::Duration::from_millis(milliseconds));
    }
    let state = AppState {
        token: Arc::from(token),
    };
    let app = Router::new()
        .route("/v1/embeddings", post(embeddings))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    println!(
        "{}",
        json!({
            "protocol_version": READINESS_PROTOCOL_VERSION,
            "base_url": format!("http://127.0.0.1:{port}/"),
            "model": MODEL_ID,
            "dimensions": DIMENSIONS,
        })
    );
    std::io::stdout().flush()?;

    axum::serve(listener, app).await?;
    Ok(())
}

fn fixture_readiness_delay(args: &[String]) -> anyhow::Result<Option<u64>> {
    let Some(index) = args
        .iter()
        .position(|argument| argument == "--fixture-delay-readiness-ms")
    else {
        return Ok(None);
    };
    let value = args
        .get(index + 1)
        .ok_or_else(|| anyhow::Error::msg("fixture readiness delay is missing a value"))?;
    Ok(Some(value.parse()?))
}

fn read_launch_token() -> anyhow::Result<String> {
    let stdin = std::io::stdin();
    let mut line = String::new();
    let mut reader = BufReader::new(stdin.lock()).take(129);
    reader.read_line(&mut line)?;
    anyhow::ensure!(
        line.ends_with('\n'),
        "launch token must be newline terminated"
    );
    let token = line.trim_end_matches(['\r', '\n']);
    anyhow::ensure!(
        token.len() == LAUNCH_TOKEN_HEX_LEN,
        "launch token has the wrong length"
    );
    anyhow::ensure!(
        token.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "launch token must be hexadecimal"
    );
    Ok(token.to_string())
}

fn monitor_parent_control_pipe() {
    std::thread::spawn(|| {
        let mut stdin = std::io::stdin();
        let mut buffer = [0_u8; 1];
        loop {
            match stdin.read(&mut buffer) {
                Ok(0) | Err(_) => std::process::exit(0),
                Ok(_) => {}
            }
        }
    });
}

async fn embeddings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<EmbeddingRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let expected = format!("Bearer {}", state.token);
    let authorized = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == expected);
    if !authorized {
        return Err(api_error(StatusCode::UNAUTHORIZED, "invalid bearer token"));
    }
    if request.model != MODEL_ID {
        return Err(api_error(StatusCode::BAD_REQUEST, "unsupported model"));
    }
    if request
        .encoding_format
        .as_deref()
        .is_some_and(|format| format != "float")
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "only float encoding is supported",
        ));
    }

    let inputs = match request.input {
        Input::One(input) => vec![input],
        Input::Many(inputs) => inputs,
    };
    if inputs.len() > MAX_BATCH {
        return Err(api_error(StatusCode::BAD_REQUEST, "batch is too large"));
    }
    if inputs.iter().any(|input| input.len() > MAX_INPUT_BYTES) {
        return Err(api_error(StatusCode::BAD_REQUEST, "input is too large"));
    }

    let data: Vec<Value> = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            json!({
                "object": "embedding",
                "index": index,
                "embedding": feature_hash(input),
            })
        })
        .collect();
    Ok(Json(json!({
        "object": "list",
        "data": data,
        "model": MODEL_ID,
        "usage": {"prompt_tokens": 0, "total_tokens": 0},
    })))
}

fn api_error(status: StatusCode, message: &str) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({"error": {"message": message, "type": "invalid_request_error"}})),
    )
}
