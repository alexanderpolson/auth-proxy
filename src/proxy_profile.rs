use aws_types::SigningService;

use hyper::{Body, Request};

use regex::Regex;

use std::error::Error;

pub type ProxyProfileResult = Result<ProxyProfile, Box<dyn Error>>;

pub struct ProxyProfileRule {
    pub path_pattern: Regex,
    pub destination_host: String,
    pub destination_service: SigningService
}

pub struct ProxyProfile {
    proxy_profiles: Vec<ProxyProfileRule>
}

impl ProxyProfile {
    pub fn new() -> ProxyProfile {
        ProxyProfile {
            proxy_profiles: vec![ProxyProfileRule {
                path_pattern: Regex::new(r"^/api/v1/crates/.+").unwrap(),
                destination_host: String::from("orbital-rust-registry.s3.amazonaws.com"),
                destination_service: signing_service("s3").unwrap(),
            }]
        }
    }

    pub fn matching_rule(self, request: &Request<Body>) -> Option<ProxyProfileRule> {
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