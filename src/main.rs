use aws_config::profile::ProfileFileCredentialsProvider;
use aws_sig_auth::middleware::Signature;
use aws_sig_auth::signer::{self, OperationSigningConfig, HttpSignatureType, RequestConfig, SigningError, SigningRequirements, SigningAlgorithm};
use aws_smithy_http::body::SdkBody;
use aws_types::SigningService;
use aws_types::credentials::ProvideCredentials;
use aws_types::region::SigningRegion;

use bytes::BytesMut;

use http_body::Body as HttpBody;

use hyper::{Body, Client, Request, Response, Server};
use hyper::http::uri::Scheme;
use hyper::service::{make_service_fn, service_fn};
use hyper_tls::HttpsConnector;
use hyper::body::Bytes;

use regex::Regex;

use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use http::StatusCode;

struct ProxyProfile {
    path_pattern: Regex,
    destination_host: String,
    destination_service: SigningService
}

struct ProxyProfileMatcher {
    proxy_profiles: Vec<ProxyProfile>
}

// TODO: Add all supported services here.
const SUPPORTED_SERVICES: [&'static str; 1] = ["s3"];

// This is necessary because creating a SigningService requires a &'static str.
fn signing_service(service_name: &str) -> Option<SigningService> {
    for supported_service in SUPPORTED_SERVICES {
        if service_name == supported_service {
            return Some(SigningService::from_static(supported_service));
        }
    }
    None
}

impl ProxyProfileMatcher {
    fn new() -> ProxyProfileMatcher {
        // TODO: Load these dynamically

        ProxyProfileMatcher {
            proxy_profiles: vec![ProxyProfile {
                path_pattern: Regex::new(r"^/api/v1/crates/.+").unwrap(),
                destination_host: String::from("orbital-rust-registry.s3.amazonaws.com"),
                destination_service: signing_service("s3").unwrap(),
            }]
        }
    }

    fn get_matching_profile(self, request: &Request<Body>) -> Option<ProxyProfile> {
        let path_and_query = request.uri().path_and_query();
        match path_and_query {
            Some(path_and_query) => {
                for proxy_profile in self.proxy_profiles {
                    if proxy_profile.path_pattern.is_match(path_and_query.path()) {
                        return Some(proxy_profile);
                    }
                }
                None
            },
            None => None
        }
    }
}

// TODO: Initialize global state appropriately
async fn hello(request: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    println!("Original Request:");
    log_request(&request);
    println!();

    // TODO: This should be initialized at start up, not with every request.
    let proxy_profile_matcher = ProxyProfileMatcher::new();
    match proxy_profile_matcher.get_matching_profile(&request) {
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

async fn sign_request(request: &mut Request<SdkBody>, proxy_profile: &ProxyProfile) -> Result<Signature, SigningError> {
    // EXPERIMENTAL AND SHOULD BE REFACTORED.

    // EXPERIMENTAL AND SHOULD BE REFACTORED.
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