use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use regex::Regex;
use std::str::FromStr;
use trust_dns_client::rr::{DNSClass, Name, RecordType};
use trust_dns_proto::op::{message::Message, query::Query};

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
        "HINFO" => RecordType::HINFO,
        "HTTPS" => RecordType::HTTPS,
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
        "SVCB" => RecordType::SVCB,
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
