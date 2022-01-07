extern crate yaml_rust;
mod proxy_profile;

use aws_config::profile::ProfileFileCredentialsProvider;
use aws_sig_auth::middleware::Signature;
use aws_sig_auth::signer::{self, OperationSigningConfig, HttpSignatureType, RequestConfig, SigningError, SigningRequirements, SigningAlgorithm};
use aws_smithy_http::body::SdkBody;
use aws_types::credentials::ProvideCredentials;
use aws_types::region::SigningRegion;

use bytes::BytesMut;

use http::StatusCode;

use http_body::Body as HttpBody;

use hyper::{Body, Client, Request, Response, Server};
use hyper::http::uri::Scheme;
use hyper::service::{make_service_fn, service_fn};
use hyper_tls::HttpsConnector;
use hyper::body::Bytes;

use std::env;
use std::fmt;
use std::fs;
use std::collections::HashMap;
use std::error::Error;
use std::time::{Duration, SystemTime};
use yaml_rust::{YamlEmitter, YamlLoader};

use proxy_profile::{ProxyProfile, ProxyProfileResult, ProxyProfileRule};

#[derive(Debug, Clone)]
struct ArgumentError;

impl fmt::Display for ArgumentError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Need to provide path to proxy profile as an argument")
    }
}

impl std::error::Error for ArgumentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

fn get_proxy_profile() -> ProxyProfileResult {
    // TODO: Load these dynamically
    let args: Vec<String> = env::args().collect();
    match args.len() {
        // 0: Executable name
        // 1: Profile file
        2 => {
            println!("Args received");
            let profile_file = args.get(1).unwrap();
            let profile_yaml_source = fs::read_to_string(profile_file).unwrap();
            println!("YAML Source: {}", profile_yaml_source);
            let profile_yaml =
                &YamlLoader::load_from_str(profile_yaml_source.as_str()).unwrap()[0];
            let mut out_str = String::new();
            let mut emitter = YamlEmitter::new(&mut out_str);
            emitter.dump(profile_yaml).unwrap();
            println!("YAML Document: {}", out_str);
            Ok(ProxyProfile::new())
        },
        _ => {
            println!("No args received");
            Err(Box::new(ArgumentError))
        }
    }
}

// TODO: Initialize global state appropriately
async fn hello(request: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    println!("Original Request:");
    log_request(&request);
    println!();

    // TODO: This should be initialized at start up, not with every request.
    // TODO: Load these dynamically
    let proxy_profile = get_proxy_profile().unwrap();
    match proxy_profile.matching_rule(&request) {
        Some(proxy_profile) => {
            // Assuming secure connection.
            // TODO: This should be initialized at start up not with every request.
            let https = HttpsConnector::new();
            let client = Client::builder().build::<_, SdkBody>(https);

            let path_and_query = request.uri().path_and_query().unwrap();
            let destination_host = proxy_profile.destination_host.clone();
            let url = hyper::Uri::builder()
                .scheme(Scheme::HTTPS)
                .authority(destination_host.clone().as_str())
                .path_and_query(path_and_query.clone())
                .build();

            let mut new_request_builder = Request::builder()
                .method(request.method())
                .uri(url.unwrap());

            // Pass on the headers
            let mut other_headers = HashMap::new();
            for (name, value) in request.headers() {
                if name.as_str() == "host" {
                    new_request_builder = new_request_builder.header(name, destination_host.as_str());
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
            sign_request(&mut new_request, &proxy_profile).await.unwrap();

            for (name, value) in other_headers {
                new_request.headers_mut().insert(name, value);
            }

            println!("Signed Request:");
            log_request(&new_request);
            println!();

            let mut response = client.request(new_request).await;
            log_response(&mut response).await;
            response
        },
        None => {
            // Return a 404
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

async fn body_to_bytes(body: &mut Body) -> Bytes {
    let mut buf = BytesMut::with_capacity(body.size_hint().lower() as usize);
    while let Some(chunk) = body.data().await {
        buf.extend_from_slice(&chunk.unwrap());
    }
    buf.freeze()
}

async fn credentials() -> aws_types::credentials::Result {
    // TODO: Customize this.
    let credentials_provider = ProfileFileCredentialsProvider::builder()
        .profile_name("orbitalCode")
        .build();
    return credentials_provider.provide_credentials().await
}

async fn sign_request(request: &mut Request<SdkBody>, proxy_profile: &ProxyProfileRule) -> Result<Signature, SigningError> {
    let credentials = credentials().await.unwrap();
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
        service: &proxy_profile.destination_service,
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
    get_proxy_profile();

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