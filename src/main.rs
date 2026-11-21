pub mod config;
pub mod dns_utils;
use anyhow::{anyhow, Context, Result};
use clap::{App, Arg};
use config::Config;
use dns_utils::{create_dns_query, parse_dns_answer};
use odoh_rs::*;
use rand::rng;
use reqwest::{
    header::{HeaderMap, ACCEPT, CACHE_CONTROL, CONTENT_TYPE},
    Client, Response,
};
use std::env;
use url::Url;

const PKG_NAME: &str = env!("CARGO_PKG_NAME");
const PKG_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

const WELL_KNOWN: &str = "/.well-known/odohconfigs";

#[derive(Clone, Debug)]
struct ClientSession {
    pub client: Client,
    pub target: Url,
    pub proxy: Option<Url>,
    pub client_secret: Option<[u8; 16]>,
    pub target_config: ObliviousDoHConfigContents,
    pub query: Option<ObliviousDoHMessagePlaintext>,
}

impl ClientSession {
    /// Create a new ClientSession
    pub async fn new(config: Config) -> Result<Self> {
        let target = Url::parse(&config.server.target)?;
        // RFC 9230 §4.1: the scheme of the Target URI MUST be "https".
        if target.scheme() != "https" {
            return Err(anyhow!("target URL must use https"));
        }
        // RFC 9230 §4.1: the Target URI, including its path, is where the target
        // is accessible, so it is used exactly as configured.
        let proxy = match &config.server.proxy {
            Some(p) => {
                let url = Url::parse(p)?;
                // RFC 9230 §4.1: the scheme of the Proxy URI MUST be "https".
                if url.scheme() != "https" {
                    return Err(anyhow!("proxy URL must use https"));
                }
                Some(url)
            }
            None => None,
        };

        // RFC 9230 leaves config discovery out of scope; deployments publish the
        // configuration at the well-known URI on the target host.
        let host = target.host_str().context("target URL has no host")?;
        let well_known = match target.port() {
            Some(port) => format!("{}://{}:{}{}", target.scheme(), host, port, WELL_KNOWN),
            None => format!("{}://{}{}", target.scheme(), host, WELL_KNOWN),
        };
        // fetch `odohconfigs` by querying well known endpoint using GET request
        let mut odohconfigs = reqwest::get(&well_known).await?.bytes().await?;
        let configs: ObliviousDoHConfigs = parse(&mut odohconfigs).context("invalid configs")?;
        let target_config = configs
            .into_iter()
            .next()
            .context("no available config")?
            .into();

        Ok(Self {
            // RFC 9230 §4.3: if a client follows a redirect, the follow-up
            // request MUST also go through a proxy. Not following redirects at
            // all is the simplest compliant behavior.
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            target,
            proxy,
            client_secret: None,
            target_config,
            query: None,
        })
    }

    /// Create an oblivious query from a domain and query type
    pub fn create_request(&mut self, domain: &str, qtype: &str) -> Result<Vec<u8>> {
        // create a DNS message
        let dns_msg = create_dns_query(domain, qtype)?;
        let query = ObliviousDoHMessagePlaintext::new(&dns_msg, 1);
        self.query = Some(query.clone());
        let mut rng = rng();
        let (oblivious_query, client_secret) = encrypt_query(&query, &self.target_config, &mut rng)
            .context("failed to encrypt query")?;
        let query_body = compose(&oblivious_query)
            .context("failed to compose query body")?
            .freeze();
        self.client_secret = Some(client_secret);
        Ok(query_body.to_vec())
    }

    /// Set headers and build an HTTP request to send the oblivious query to the proxy/target.
    /// If a proxy is specified, the request will be sent to the proxy. However, if a proxy is absent,
    /// it will be sent directly to the target. Note that not specifying a proxy effectively nullifies
    /// the entire purpose of using ODoH.
    pub async fn send_request(&mut self, request: &[u8]) -> Result<Response> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, ODOH_HTTP_HEADER.parse()?);
        headers.insert(ACCEPT, ODOH_HTTP_HEADER.parse()?);
        headers.insert(CACHE_CONTROL, "no-cache, no-store".parse()?);
        let query = [
            (
                "targethost",
                self.target
                    .host_str()
                    .context("Target host is not a valid host string")?,
            ),
            ("targetpath", self.target.path()),
        ];
        let builder = if let Some(p) = &self.proxy {
            self.client.post(p.clone()).headers(headers).query(&query)
        } else {
            self.client.post(self.target.clone()).headers(headers)
        };
        let resp = builder.body(request.to_vec()).send().await?;
        Ok(resp)
    }

    /// Parse the received response from the resolver and print the answer.
    pub async fn parse_response(&self, resp: Response) -> Result<()> {
        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        validate_response(resp.status(), content_type)?;
        let mut data = resp.bytes().await?;
        let response_body = parse(&mut data).context("failed to parse response body")?;
        let response = decrypt_response(
            &self.query.clone().unwrap(),
            &response_body,
            self.client_secret.unwrap(),
        )
        .context("failed to decrypt response")?;
        parse_dns_answer(&response.into_msg())?;
        Ok(())
    }
}

/// Validate an ODoH response before processing its payload.
///
/// RFC 9230 §4.3:
/// - a successful response uses a 2xx status code;
/// - a client MUST only process a response that carries the
///   application/oblivious-dns-message Content-Type.
fn validate_response(status: reqwest::StatusCode, content_type: Option<&str>) -> Result<()> {
    if !status.is_success() {
        return Err(anyhow!(
            "query failed with response status code {}",
            status.as_u16()
        ));
    }
    if content_type != Some(ODOH_HTTP_HEADER) {
        return Err(anyhow!(
            "query failed: response Content-Type is {:?}, expected {}",
            content_type.unwrap_or(""),
            ODOH_HTTP_HEADER
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_response;
    use odoh_rs::ODOH_HTTP_HEADER;
    use reqwest::StatusCode;

    #[test]
    fn accepts_2xx_with_odoh_content_type() {
        assert!(validate_response(StatusCode::OK, Some(ODOH_HTTP_HEADER)).is_ok());
        assert!(validate_response(StatusCode::CREATED, Some(ODOH_HTTP_HEADER)).is_ok());
    }

    #[test]
    fn rejects_non_2xx() {
        assert!(validate_response(StatusCode::BAD_REQUEST, Some(ODOH_HTTP_HEADER)).is_err());
        assert!(
            validate_response(StatusCode::INTERNAL_SERVER_ERROR, Some(ODOH_HTTP_HEADER)).is_err()
        );
    }

    #[test]
    fn rejects_missing_content_type() {
        assert!(validate_response(StatusCode::OK, None).is_err());
    }

    #[test]
    fn rejects_wrong_content_type() {
        assert!(validate_response(StatusCode::OK, Some("text/plain")).is_err());
        assert!(validate_response(StatusCode::OK, Some("application/dns-message")).is_err());
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let matches = App::new(PKG_NAME)
        .version(PKG_VERSION)
        .author(PKG_AUTHORS)
        .about(PKG_DESCRIPTION)
        .arg(
            Arg::with_name("config_file")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Path to the config.toml config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("domain")
                .help("Domain to query")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("type")
                .help("Query type")
                .required(true)
                .index(2),
        )
        .get_matches();

    let config_file = matches
        .value_of("config_file")
        .unwrap_or("tests/config.toml");
    let config = Config::from_path(config_file)?;
    let domain = matches.value_of("domain").unwrap();
    let qtype = matches.value_of("type").unwrap();
    let mut session = ClientSession::new(config.clone()).await?;
    let request = session.create_request(domain, qtype)?;
    let response = session.send_request(&request).await?;
    session.parse_response(response).await?;
    Ok(())
}
