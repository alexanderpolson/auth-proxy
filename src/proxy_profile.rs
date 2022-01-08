use aws_types::SigningService;

use hyper::{Body, Request};

use regex::Regex;

use std::error::Error;
use std::fmt;
use yaml_rust::Yaml;

#[derive(Debug, Clone)]
pub struct ArgumentError;

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
    pub fn new(profile_yaml: &Yaml) -> ProxyProfileResult {
        match &profile_yaml.as_vec() {
            Some(profile_rules) => {
                let rules =
                    profile_rules.iter().map(|rule_yaml| rule_for_yaml(rule_yaml).unwrap()).collect();
                Ok(ProxyProfile {
                    proxy_profiles: rules
                })
            },
            None => Err(Box::new(ArgumentError))
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

fn rule_for_yaml(rule_yaml: &Yaml) -> Result<ProxyProfileRule, ArgumentError> {
    Ok(ProxyProfileRule {
        path_pattern: Regex::new(rule_yaml["path_pattern"].as_str().unwrap()).unwrap(),
        destination_host: String::from(rule_yaml["destination_host"].as_str().unwrap()),
        destination_service: signing_service(rule_yaml["destination_service"].as_str().unwrap()).unwrap(),
    })
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