use http::uri::PathAndQuery;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server};
use hyper::http::uri::{Authority, Scheme};
use hyper_tls::HttpsConnector;

fn get_path_and_query(path_and_query: Option<&PathAndQuery>) -> PathAndQuery {
    match path_and_query {
        Some(path_and_query) => path_and_query.clone(),
        None => PathAndQuery::from_static("/")
    }
}

async fn hello(request: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    // log_request(&request);
    // Assuming secure connection for now.
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, Body>(https);
    let path_and_query = request.uri().path_and_query();
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
    let new_request = new_request_builder.body(request.into_body()).unwrap();
    // log_request(&new_request);
    let response = client.request(new_request).await;
    // log_response(&response);
    response
}

fn log_request(request: &Request<Body>) {
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