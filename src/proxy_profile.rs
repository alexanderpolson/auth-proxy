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
    pub proxy_host: String,
    pub proxy_request_path_and_query: String,
    pub destination_service: SigningService
}

pub struct MatchedProfileRule {
    pub proxy_host: String,
    pub resolved_path_and_query: String,
    pub request_service: SigningService,
}

pub struct ProxyProfile {
    pub aws_profile: Option<String>,
    rules: Vec<ProxyProfileRule>
}

impl ProxyProfile {
    pub fn new(profile_yaml: &Yaml) -> ProxyProfileResult {
        let aws_profile = match profile_yaml["aws_profile"].as_str() {
            Some(profile_name_str) =>  Some(String::from(profile_name_str)),
            None => None
        };

        let profile_rules = &profile_yaml["rules"].as_vec();
        match profile_rules {
            Some(profile_rules) => {
                let rules =
                    profile_rules.iter().map(|rule_yaml| rule_for_yaml(rule_yaml).unwrap()).collect();
                Ok(ProxyProfile {
                    aws_profile: aws_profile,
                    rules: rules
                })
            },
            None => Err(Box::new(ArgumentError))
        }
    }

    pub fn match_rule(self, path_and_query: &str) -> Option<MatchedProfileRule> {
        for profile_rule in self.rules {
            if let Some(captures) = profile_rule.path_pattern.captures(path_and_query) {
                let mut resolved_path_and_query = profile_rule.proxy_request_path_and_query.clone();
                for (index, capture) in captures.iter().enumerate() {
                    resolved_path_and_query = resolved_path_and_query.replace(format!("${}", index).as_str(), capture.unwrap().as_str());
                }
                return Some(MatchedProfileRule {
                    proxy_host: profile_rule.proxy_host,
                    resolved_path_and_query,
                    request_service: profile_rule.destination_service,
                });
            }
        }
        None
    }

    pub fn match_rule_for_request(self, request: &Request<Body>) -> Option<MatchedProfileRule> {
        let path_and_query = request.uri().path_and_query();
        match path_and_query {
            Some(path_and_query) => {
                self.match_rule(path_and_query.as_str())
            },
            None => None
        }
    }
}

fn rule_for_yaml(rule_yaml: &Yaml) -> Result<ProxyProfileRule, ArgumentError> {
    Ok(ProxyProfileRule {
        path_pattern: Regex::new(rule_yaml["path_pattern"].as_str().unwrap()).unwrap(),
        proxy_host: String::from(rule_yaml["proxy_host"].as_str().unwrap()),
        proxy_request_path_and_query: String::from(rule_yaml["proxy_request_path_and_query"].as_str().unwrap()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_test() -> Result<(), String> {
        let rule = ProxyProfileRule {
            proxy_host: String::from("some_host"),
            path_pattern: Regex::new("^/project/api/v1/crates/(.+)").unwrap(),
            destination_service: signing_service("s3").unwrap(),
            proxy_request_path_and_query: String::from("/api/v1/crates/$1"),
        };
        let profile = ProxyProfile {
            aws_profile: None,
            rules: vec![rule],
        };

        let matched_rule = profile.match_rule("/project/api/v1/crates/blahblah");
        if let Some(matched_rule) = matched_rule {
            assert_eq!(matched_rule.resolved_path_and_query, "/api/v1/crates/blahblah");
            return Ok(());
        }
        Err(String::from("Rule was not properly matched"))
    }
}