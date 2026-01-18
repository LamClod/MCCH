use axum::body::Body;
use axum::http::{header, HeaderValue, Response, StatusCode, Uri};
use include_dir::{include_dir, Dir};

static ASSETS: Dir = include_dir!("$CARGO_MANIFEST_DIR/assets");

pub async fn static_handler(uri: Uri) -> Response<Body> {
    let path = uri.path().trim_start_matches('/');
    let asset_path = if path.is_empty() { "index.html" } else { path };

    if let Some(file) = ASSETS.get_file(asset_path) {
        return file_response(file.contents(), asset_path);
    }

    if let Some(index) = ASSETS.get_file("index.html") {
        return file_response(index.contents(), "index.html");
    }

    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("missing asset"))
        .unwrap_or_else(|_| Response::new(Body::from("missing asset")))
}

fn file_response(contents: &[u8], path: &str) -> Response<Body> {
    let mut builder = Response::builder().status(StatusCode::OK);
    if let Some(mime) = mime_guess::from_path(path).first() {
        if let Ok(value) = HeaderValue::from_str(mime.as_ref()) {
            builder = builder.header(header::CONTENT_TYPE, value);
        }
    }
    builder
        .body(Body::from(contents.to_vec()))
        .unwrap_or_else(|_| Response::new(Body::from(contents.to_vec())))
}

