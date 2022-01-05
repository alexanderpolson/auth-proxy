use bytes::BytesMut;
use http::uri::PathAndQuery;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server};
use hyper::http::uri::{Authority, Scheme};
use hyper_tls::HttpsConnector;
use std::time::{Duration, SystemTime};
use aws_config::profile::ProfileFileCredentialsProvider;
use aws_sig_auth::middleware::Signature;
use aws_sig_auth::signer::{self, OperationSigningConfig, HttpSignatureType, RequestConfig, SigningError};
use aws_smithy_http::body::SdkBody;
use aws_types::SigningService;
use aws_types::credentials::ProvideCredentials;
use aws_types::region::SigningRegion;
use http_body::Body as HttpBody;
use hyper::body::Bytes;

fn get_path_and_query(path_and_query: Option<&PathAndQuery>) -> PathAndQuery {
    match path_and_query {
        Some(path_and_query) => path_and_query.clone(),
        None => PathAndQuery::from_static("/")
    }
}

async fn hello(request: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    // Assuming secure connection for now.
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, SdkBody>(https);
    let path_and_query = request.uri().path_and_query();

    // TODO: Make this configurable.
    let host = "www.google.com";
    let url = hyper::Uri::builder()
        .scheme(Scheme::HTTPS)
        .authority(Authority::from_static(host))
        .path_and_query(get_path_and_query(path_and_query))
        .build();

    let mut new_request_builder = Request::builder()
        .method(request.method())
        .uri(url.unwrap());

    // Pass on the headers
    for (name, value) in request.headers() {
        if name.as_str() == "host" {
            new_request_builder = new_request_builder.header(name, host);
        } else {
            new_request_builder = new_request_builder.header(name, value);
        }
    }

    // https://users.rust-lang.org/t/read-hyper-body-without-modification-to-it/45446/6
    let buffer: Bytes = {
        let mut body = request.into_body();
        let mut buf = BytesMut::with_capacity(body.size_hint().lower() as usize);
        while let Some(chunk) = body.data().await {
            buf.extend_from_slice(&chunk?);
        }
        buf.freeze()
    };
    // Sign the request.
    // https://docs.rs/aws-sig-auth/latest/aws_sig_auth/
    let sdk_body: SdkBody = SdkBody::from(buffer);
    let mut new_request = new_request_builder.body(sdk_body).unwrap();
    sign_request(&mut new_request).await.unwrap();
    log_request(&new_request);
    let response = client.request(new_request).await;
    log_response(&response);
    response
}

async fn sign_request(request: &mut Request<SdkBody>) -> Result<Signature, SigningError> {
    // Get credentials.
    let credentials_provider = ProfileFileCredentialsProvider::builder()
        .profile_name("orbitalCode")
        .build();
    let credentials = credentials_provider.provide_credentials().await?;
    let signer = signer::SigV4Signer::new();
    let mut operation_config = OperationSigningConfig::default_config();
    operation_config.signature_type = HttpSignatureType::HttpRequestHeaders;
    operation_config.expires_in = Some(Duration::from_secs(15));
    let request_config = RequestConfig {
        request_ts: SystemTime::now(),
        region: &SigningRegion::from_static("us-west-2"),
        service: &SigningService::from_static(""),
        payload_override: None,
    };

    signer.sign(&operation_config, &request_config, &credentials, request)
}

fn log_request(request: &Request<SdkBody>) {
    println!("Method: {}", request.method());
    println!("URI: {}", request.uri());
    for (name, value) in request.headers() {
        println!("Header: {} = {}", name, value.to_str().unwrap());
    }
}

fn log_response(result: &Result<Response<Body>, hyper::Error>) {
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

    let addr = ([127, 0, 0, 1], 3000).into();

    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on https://{}", addr);

    server.await?;

    Ok(())
}