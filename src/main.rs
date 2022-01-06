use bytes::BytesMut;
use http::uri::PathAndQuery;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server};
use hyper::http::uri::{Authority, Scheme};
use hyper_tls::HttpsConnector;
use std::time::{Duration, SystemTime};
use aws_config::profile::ProfileFileCredentialsProvider;
use aws_sig_auth::middleware::Signature;
use aws_sig_auth::signer::{self, OperationSigningConfig, HttpSignatureType, RequestConfig, SigningError, SigningRequirements, SigningAlgorithm};
use aws_smithy_http::body::SdkBody;
use aws_types::SigningService;
use aws_types::credentials::ProvideCredentials;
use aws_types::region::SigningRegion;
use http_body::Body as HttpBody;
use hyper::body::Bytes;
use std::collections::HashMap;

fn get_path_and_query(path_and_query: Option<&PathAndQuery>) -> PathAndQuery {
    match path_and_query {
        Some(path_and_query) => path_and_query.clone(),
        None => PathAndQuery::from_static("/")
    }
}

async fn hello(request: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    println!("Original Request:");
    log_request(&request);
    println!();

    // Assuming secure connection for now.
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, SdkBody>(https);
    let path_and_query = request.uri().path_and_query();

    // TODO: Make this configurable.
    let host = "orbital-rust-registry.s3.amazonaws.com";
    let url = hyper::Uri::builder()
        .scheme(Scheme::HTTPS)
        .authority(Authority::from_static(host))
        .path_and_query(get_path_and_query(path_and_query))
        .build();

    let mut new_request_builder = Request::builder()
        .method(request.method())
        .uri(url.unwrap());

    // Pass on the headers
    let mut other_headers = HashMap::new();
    for (name, value) in request.headers() {
        if name.as_str() == "host" {
            new_request_builder = new_request_builder.header(name, host);
        } else if name.as_str() == "x-amz-content-sha256" || name.as_str() == "x-amz-date" {
            new_request_builder = new_request_builder.header(name, value);
        } else {
            // Track other headers and add them back after signing so as not to break the signing
            // process. If we include these when signing, requests that are made are rejected because
            // the produced signatures don't match.
            other_headers.insert(name.clone(), value.clone());
        }
    }

    // https://users.rust-lang.org/t/read-hyper-body-without-modification-to-it/45446/6
    let mut original_body = request.into_body();
    let buffer = body_to_bytes(&mut original_body).await;

    println!("Body length: {}", buffer.len());
    // Sign the request.
    // https://docs.rs/aws-sig-auth/latest/aws_sig_auth/
    let sdk_body = if buffer.is_empty() {
        SdkBody::empty()
    } else {
        SdkBody::from(buffer)
    };
    let mut new_request = new_request_builder.body(sdk_body).unwrap();

    println!("Updated Request:");
    log_request(&new_request);
    sign_request(&mut new_request).await.unwrap();

    for (name, value) in other_headers {
        new_request.headers_mut().insert(name, value);
    }

    println!("Signed Request:");
    log_request(&new_request);
    println!();

    let mut response = client.request(new_request).await;
    log_response(&mut response).await;
    response
}

async fn body_to_bytes(body: &mut Body) -> Bytes {
    let mut buf = BytesMut::with_capacity(body.size_hint().lower() as usize);
    while let Some(chunk) = body.data().await {
        buf.extend_from_slice(&chunk.unwrap());
    }
    buf.freeze()
}

async fn sign_request(request: &mut Request<SdkBody>) -> Result<Signature, SigningError> {
    // Get credentials.
    // TODO: Customize this.
    let credentials_provider = ProfileFileCredentialsProvider::builder()
        .profile_name("orbitalCode")
        .build();
    let credentials = credentials_provider.provide_credentials().await?;
    let signer = signer::SigV4Signer::new();
    let mut operation_config = OperationSigningConfig::default_config();
    operation_config.signature_type = HttpSignatureType::HttpRequestHeaders;
    operation_config.signing_options.content_sha256_header = true;
    operation_config.signing_requirements = SigningRequirements::Required;
    operation_config.expires_in = Some(Duration::from_secs(15 * 60));
    operation_config.algorithm = SigningAlgorithm::SigV4;
    let request_config = RequestConfig {
        request_ts: SystemTime::now(),
        region: &SigningRegion::from_static("us-west-2"),
        service: &SigningService::from_static("s3"),
        payload_override: None,
    };

    signer.sign(&operation_config, &request_config, &credentials, request)
}

fn log_request<T: HttpBody>(request: &Request<T>) {
    println!("Method: {}", request.method());
    println!("URI: {}", request.uri());
    for (name, value) in request.headers() {
        println!("Header: {} = {}", name, value.to_str().unwrap());
    }
}

async fn log_response(result: &mut Result<Response<Body>, hyper::Error>) {
    match result {
        Ok(response) => {
            println!("Status: {}", response.status());
        },
        Err(err) => {
            println!("Error: {}", err);
        }
    };
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    pretty_env_logger::init();

    // For every connection, we must make a `Service` to handle all
    // incoming HTTP requests on said connection.
    let make_svc = make_service_fn(|_conn| {
        // This is the `Service` that will handle the connection.
        // `service_fn` is a helper to convert a function that
        // returns a Response into a `Service`.
        async { Ok::<_, hyper::Error>(service_fn(hello)) }
    });

    let addr = ([127, 0, 0, 1], 8123).into();

    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on https://{}", addr);

    server.await?;

    Ok(())
}