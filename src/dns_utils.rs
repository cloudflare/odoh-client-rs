use anyhow::{anyhow, Result};
use futures::future::{self, Either};
use lazy_static::lazy_static;
use regex::Regex;
use std::str::FromStr;
use tokio::net::UdpSocket;
use trust_dns_client::rr::{DNSClass, Name, RData, RecordType};
use trust_dns_client::{
    client::{AsyncClient, ClientHandle},
    udp::UdpClientStream,
};
use trust_dns_proto::op::{message::Message, query::Query};

const CONFIG_RESOLVER: &str = "1.1.1.1:53";
const CONFIG_DOMAIN: &str = "odoh.cloudflare-dns.com";
const HTTPS_RECORD_CODE: u16 = 65;
const ODOH_VERSION: &str = "ff03";

/// Matches "TYPExxx..", where x is a number, returns xxx... parsed as u16
/// Example: "TYPE45" returns 45
fn parse_unknown_qtype(qtype: &str) -> Result<u16> {
    lazy_static! {
        pub static ref RE: Regex = Regex::new(r"^(TYPE)(\d+)$").unwrap();
    }
    if RE.is_match(qtype) {
        let mut captures = RE.captures_iter(qtype);
        return Ok(captures.next().unwrap()[2].parse::<u16>()?);
    }
    Err(anyhow!("Not a valid qtype"))
}

/// Creates a DNS query from a given domain and query type
pub fn create_dns_query(domain: &str, query_type: &str) -> Result<Vec<u8>> {
    let name = Name::from_str(domain)?;
    let mut query = Query::query(name, get_qtype(query_type)?);
    query.set_query_class(DNSClass::IN);
    let mut msg = Message::new();
    msg.add_query(query);
    msg.set_recursion_desired(true);
    let id: u16 = rand::random();
    msg.set_id(id);
    let msg_as_bytes = msg.to_vec()?;
    Ok(msg_as_bytes)
}

/// Parses a DNS answer from bytes and prints it
pub fn parse_dns_answer(msg: &[u8]) -> Result<()> {
    let result = Message::from_vec(msg)?;
    println!("Response: {:?}", result.answers());
    Ok(())
}

/// Fetches `odohconfig` by querying the target server for HTTPS records.
/// Currently supports `odoh.cloudflare-dns.com.`.
pub async fn fetch_odoh_config(target: &str) -> Result<Vec<u8>> {
    target
        .find(CONFIG_DOMAIN)
        .ok_or_else(|| anyhow!("Target not supported"))?;

    let address = CONFIG_RESOLVER.parse()?;
    let conn = UdpClientStream::<UdpSocket>::new(address);
    let (mut client, bg) = AsyncClient::connect(conn).await?;
    let name = Name::from_str(CONFIG_DOMAIN)?;
    let query = client.query(name, DNSClass::IN, RecordType::Unknown(HTTPS_RECORD_CODE));
    let response = match future::select(query, bg).await {
        Either::Left((dns_resp, _)) => dns_resp?,
        _ => {
            return Err(anyhow!(
                "odohconfig fetch failed, dns response was not returned"
            ))
        }
    };

    let answer = response.answers()[0].rdata();
    if let RData::Unknown { code, rdata } = answer.clone() {
        assert_eq!(code, HTTPS_RECORD_CODE);
        let data = rdata
            .anything()
            .ok_or_else(|| anyhow!("odohconfig fetch failed, dns response buf is empty"))?;
        odohconfig_from_https(data)
    } else {
        return Err(anyhow!(
            "Incorrect record type returned, could not fetch odohconfig"
        ));
    }
}

/// Parses https record and returns odohconfig value.
/// Currently, this parser is a hack that just looks for ODOH_VERSION in the
/// data and extracts the relevant data around it. This should be replaced
/// with a function from the dns library that is HTTPS record aware and can
/// parse keys.
fn odohconfig_from_https(data: &[u8]) -> Result<Vec<u8>> {
    let data_hex = hex::encode(data);
    let vec = data_hex.split(ODOH_VERSION).collect::<Vec<_>>();
    let first_len = vec.first().unwrap().len();
    let odohconfig_len = vec.first().unwrap().to_string().split_off(first_len - 4);
    let odohconfig = format!(
        "{}{}{}",
        odohconfig_len,
        ODOH_VERSION,
        vec.last()
            .ok_or_else(|| anyhow!("odohconfig not present in HTTPS record"))?
    );
    Ok(hex::decode(odohconfig)?)
}

/// Parse record type enum from &str
fn get_qtype(qtype: &str) -> Result<RecordType> {
    let rtype = match qtype {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "ANAME" => RecordType::ANAME,
        "ANY" => RecordType::ANY,
        "AXFR" => RecordType::AXFR,
        "CAA" => RecordType::CAA,
        "CNAME" => RecordType::CNAME,
        "IXFR" => RecordType::IXFR,
        "MX" => RecordType::MX,
        "NAPTR" => RecordType::NAPTR,
        "NS" => RecordType::NS,
        "NULL" => RecordType::NULL,
        "OPENPGPKEY" => RecordType::OPENPGPKEY,
        "OPT" => RecordType::OPT,
        "PTR" => RecordType::PTR,
        "SOA" => RecordType::SOA,
        "SRV" => RecordType::SRV,
        "SSHFP" => RecordType::SSHFP,
        "TLSA" => RecordType::TLSA,
        "TXT" => RecordType::TXT,
        "ZERO" => RecordType::ZERO,
        _ => match parse_unknown_qtype(qtype) {
            Ok(n) => RecordType::Unknown(n),
            Err(_) => return Err(anyhow!("Record type is invalid")),
        },
    };
    Ok(rtype)
}
