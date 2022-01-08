# Auth Proxy
`auth-proxy` provides a local server that you can point command-line tools to when those commands require, but don't provide an authentication mechanism. For example, if you want to access a secure S3 bucket via a simple curl command, you wouldn't be able to do so without the request being authenticated in somewhere.

Assuming you're authorized to access the bucket, you can configure auth-proxy with your desired AWS profile and request patterns, and then make the curl request to the local service, which will intercept the request, add appropriate authorization, and then "forward" the request on to the configured endpoint.

## Why?
This tool was originally written with private [Rust registries](https://doc.rust-lang.org/cargo/reference/registries.html) in mind. As of v1 of the registry spec, there is a simple authentication method that allows you to control access to a registry's index, but that same mechanism doesn't apply to downloading thea ctual crates (source code).

I wanted to create a mechanism with which I could control access to a private Rust registry via AWS IAM, and keep certain Rust-based projects for private use only.

## Features
* Simple command-line interface
* Define routing rules via YAML-based profile
* Request that are routed through auth-proxy are signed with AWS SigV4 based on an AWS CLI Profile you have defined.

### TO DO
(not in any particular order, add these to the GitHub issue tracker)
* Always authenticates with us-west-2 AWS region. Need to make this customizable in the profiles.
* Better error and help messaging. Currently, if some input is incorrect, auth-proxy just panics.
* Ability to run as a one off. Currently, auth-proxy will run until manually killed. to be able to pass a command to auth-proxy on the command-line and have it exit when done would be nice.
* Distribute a Docker image that runs auth-proxy indefiitely.
* Implement other auth mechanisms?
* If an AWS profile name isn't specified in the proxy profile, assume that the "default" profile should be used. 
* Add more supported services. 
* Allow proxy rules to replace more than just host name.
* Make the port auth-proxy runs on customizable.

## How to Use
`auth-proxy` currently only supports authentication using [AWS SigV4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html). As such, the general intention is that `auth-proxy` is used to authenticate to secure AWS-based resources (such as S3 buckets), so you'll need an AWS account, some secured resources, and a user or role that you've configured in IAM and via the AWS CLI.

### Installation

#### Rust and Related Tools
In order to install `auth-proxy`, you'll need to first install Rust:
* [UNX-based OS (Linux MacOS) instructions](https://www.rust-lang.org/learn/get-started)
* [Other installation methods](https://forge.rust-lang.org/infra/other-installation-methods.html)

#### AWS CLI (optional)
Chances are, if you're working with AWS services in any capacity, you already have [the AWS CLI](https://aws.amazon.com/cli/) installed. While you won't necessarily use the AWS CLI, it can be useful for verifying that you have access to the resources that you're looking to interact with, and [the getting started and related instructions](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-welcome.html) will help you to setup a proper authentication profile.

#### auth-proxy
Once Rust is installed, you can now install `auth-proxy` by running the following command from your command-line:

``cargo install auth-proxy``

### Creating a Profile
In order for `auth-proxy` to know how to route requests, you need to point it towards a profile that you create for it. This includes details of the AWS profile to use, and the rules associated with request routing. Proxy profiles are defined using [YAML](https://yaml.org/), a relatively simple, easy to read text file format.

Here's an example profile that includes a single rule that routes requests of a particular pattern to S3.

```yaml
# This is the AWS credentials profile to use for signing requests.
aws_profile: code

# The list of rules that are used to route requests from the originally made
# requests. They are evaluated from top to bottom and the first matching
# rule is what is used to reroute the request. If no rules match, than a 404
# is returned to the calling client.
rules:
  -
    # The regular expression to match the requested path.
    path_pattern: "^/api/v1/crates/.+"
    # The new host name to route matching requests to.
    destination_host: some-s3-bucket.s3.amazonaws.com
    # The service name to use when signing the request.
    destination_service: s3
```

### Running auth-proxy
Once your profile is created, you can then run it via:

``auth-proxy PATH_TO_PROFILE``

...at which point, it will start listening on port 8123. To verify it works as expected, you can make an example request, in this case pulling a file from a secured bucket that the desired AWS profile has access to:

``curl https://localhost:8123/path/to/file.txt``

...which will be rerouted to the following URL after being properly signed.

``https://some-s3-bucket.s3.amazonaws.com/path/to/file.txt``