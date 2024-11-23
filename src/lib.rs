use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt::Debug;
use std::io::{Error, ErrorKind, Write};
use std::iter::FromIterator;
use std::net::TcpStream;
use std::sync::Arc;
use x509_parser::objects::*;
use x509_parser::{extensions::*, parse_x509_certificate};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ServerCert {
    pub common_name: String,
    pub signature_algorithm: String,
    pub sans: Vec<String>,
    pub country: String,
    pub state: String,
    pub locality: String,
    pub organization: String,
    pub not_after: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub issuer: String,
    pub is_valid: bool,
    pub time_to_expiration: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct IntermediateCert {
    pub common_name: String,
    pub signature_algorithm: String,
    pub country: String,
    pub state: String,
    pub locality: String,
    pub organization: String,
    pub not_after: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub issuer: String,
    pub is_valid: bool,
    pub time_to_expiration: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Cert {
    pub server: ServerCert,
    pub intermediate: IntermediateCert,
}

pub struct CheckSSL();

impl CheckSSL {
    /// Check ssl from domain with port 443
    ///
    /// Example
    ///
    /// ```no_run
    /// use checkssl::CheckSSL;
    ///
    /// match CheckSSL::from_domain_with_port("rust-lang.org", "443") {
    ///   Ok(certificate) => {
    ///     // do something with certificate
    ///     assert!(certificate.server.is_valid);
    ///   }
    ///   Err(e) => {
    ///     // ssl invalid
    ///     eprintln!(e);
    ///   }
    /// }
    /// ```
    pub fn from_domain_with_port(domain: &'static str, port: &str) -> Result<Cert, std::io::Error> {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let rc_config = Arc::new(config);
        let site = domain.try_into().unwrap();

        let mut sess = rustls::ClientConnection::new(rc_config, site).unwrap();
        let mut sock = TcpStream::connect(format!("{}:{}", domain, port))?;
        let mut tls = rustls::Stream::new(&mut sess, &mut sock);

        let req = format!(
            "GET / HTTP/1.0\r\nHost: {}\r\nConnection: \
                               close\r\nAccept-Encoding: identity\r\n\r\n",
            domain
        );
        tls.write_all(req.as_bytes())?;

        let mut server_cert = ServerCert {
            common_name: "".to_string(),
            signature_algorithm: "".to_string(),
            sans: Vec::new(),
            country: "".to_string(),
            state: "".to_string(),
            locality: "".to_string(),
            organization: "".to_string(),
            not_after: Utc::now(),
            not_before: Utc::now(),
            issuer: "".to_string(),
            is_valid: false,
            time_to_expiration: "".to_string(),
        };

        let mut intermediate_cert = IntermediateCert {
            common_name: "".to_string(),
            signature_algorithm: "".to_string(),
            country: "".to_string(),
            state: "".to_string(),
            locality: "".to_string(),
            organization: "".to_string(),
            not_after: Utc::now(),
            not_before: Utc::now(),
            issuer: "".to_string(),
            is_valid: false,
            time_to_expiration: "".to_string(),
        };

        if let Some(certificates) = tls.conn.peer_certificates() {
            for certificate in certificates.iter() {
                let x509cert = match parse_x509_certificate(certificate.as_ref()) {
                    Ok((_, x509cert)) => x509cert,
                    Err(e) => return Err(Error::new(ErrorKind::Other, e.to_string())),
                };

                let is_ca = match x509cert.tbs_certificate.basic_constraints().unwrap() {
                    Some(basic_extension) => basic_extension.value.ca,
                    None => false,
                };

                //check if it's ca or not, if ca then insert to intermediate certificate
                if is_ca {
                    intermediate_cert.is_valid = x509cert.validity().is_valid();
                    intermediate_cert.not_after = Utc
                        .timestamp_opt(x509cert.tbs_certificate.validity.not_after.timestamp(), 0)
                        .unwrap();
                    intermediate_cert.not_before = Utc
                        .timestamp_opt(x509cert.tbs_certificate.validity.not_before.timestamp(), 0)
                        .unwrap();

                    match oid2sn(&x509cert.signature_algorithm.algorithm, oid_registry()) {
                        Ok(s) => {
                            intermediate_cert.signature_algorithm = s.to_string();
                        }
                        Err(_e) => {
                            return Err(Error::new(
                                ErrorKind::Other,
                                "Error converting Oid to Nid".to_string(),
                            ))
                        }
                    }

                    if let Some(time_to_expiration) =
                        x509cert.tbs_certificate.validity.time_to_expiration()
                    {
                        intermediate_cert.time_to_expiration = format!(
                            "{:?} day(s)",
                            time_to_expiration.whole_seconds() / 60 / 60 / 24
                        )
                    }

                    let issuer = x509cert.issuer();
                    let subject = x509cert.subject();

                    for rdn_seq in issuer.iter() {
                        for attr_key_val in rdn_seq.iter() {
                            match oid2sn(attr_key_val.attr_type(), oid_registry()) {
                                Ok(s) => {
                                    let rdn_content =
                                        attr_key_val.attr_value().as_str().unwrap().to_string();
                                    if s == "CN" {
                                        intermediate_cert.issuer = rdn_content;
                                    }
                                }
                                Err(_e) => {
                                    return Err(Error::new(
                                        ErrorKind::Other,
                                        "Error converting Oid to Nid".to_string(),
                                    ))
                                }
                            }
                        }
                    }
                    for rdn_seq in subject.iter() {
                        for attr_key_val in rdn_seq.iter() {
                            match oid2sn(attr_key_val.attr_type(), oid_registry()) {
                                Ok(s) => {
                                    let rdn_content =
                                        attr_key_val.attr_value().as_str().unwrap().to_string();
                                    match s {
                                        "C" => intermediate_cert.country = rdn_content,
                                        "ST" => intermediate_cert.state = rdn_content,
                                        "L" => intermediate_cert.locality = rdn_content,
                                        "CN" => intermediate_cert.common_name = rdn_content,
                                        "O" => intermediate_cert.organization = rdn_content,
                                        _ => {}
                                    }
                                }
                                Err(_e) => {
                                    return Err(Error::new(
                                        ErrorKind::Other,
                                        "Error converting Oid to Nid".to_string(),
                                    ))
                                }
                            }
                        }
                    }
                } else {
                    server_cert.is_valid = x509cert.validity().is_valid();
                    server_cert.not_after = Utc
                        .timestamp_opt(x509cert.tbs_certificate.validity.not_after.timestamp(), 0)
                        .unwrap();
                    server_cert.not_before = Utc
                        .timestamp_opt(x509cert.tbs_certificate.validity.not_before.timestamp(), 0)
                        .unwrap();

                    match oid2sn(&x509cert.signature_algorithm.algorithm, oid_registry()) {
                        Ok(s) => {
                            server_cert.signature_algorithm = s.to_string();
                        }
                        Err(_e) => {
                            return Err(Error::new(
                                ErrorKind::Other,
                                "Error converting Oid to Nid".to_string(),
                            ))
                        }
                    }

                    if let Some(san) = x509cert.tbs_certificate.subject_alternative_name().unwrap()
                    {
                        for name in san.value.general_names.iter() {
                            match name {
                                GeneralName::DNSName(dns) => server_cert.sans.push(dns.to_string()),
                                _ => {}
                            }
                        }
                    }

                    if let Some(time_to_expiration) =
                        x509cert.tbs_certificate.validity.time_to_expiration()
                    {
                        server_cert.time_to_expiration = format!(
                            "{:?} day(s)",
                            time_to_expiration.whole_seconds() / 60 / 60 / 24
                        )
                    }

                    let issuer = x509cert.issuer();
                    let subject = x509cert.subject();

                    for rdn_seq in issuer.iter() {
                        for attr_key_val in rdn_seq.iter() {
                            match oid2sn(attr_key_val.attr_type(), oid_registry()) {
                                Ok(s) => {
                                    let rdn_content =
                                        attr_key_val.attr_value().as_str().unwrap().to_string();
                                    if s == "CN" {
                                        server_cert.issuer = rdn_content;
                                    }
                                }
                                Err(_e) => {
                                    return Err(Error::new(
                                        ErrorKind::Other,
                                        "Error converting Oid to Nid".to_string(),
                                    ))
                                }
                            }
                        }
                    }

                    for rdn_seq in subject.iter() {
                        for attr_key_val in rdn_seq.iter() {
                            match oid2sn(attr_key_val.attr_type(), oid_registry()) {
                                Ok(s) => {
                                    let rdn_content =
                                        attr_key_val.attr_value().as_str().unwrap().to_string();
                                    match s {
                                        "C" => server_cert.country = rdn_content,
                                        "ST" => server_cert.state = rdn_content,
                                        "L" => server_cert.locality = rdn_content,
                                        "CN" => server_cert.common_name = rdn_content,
                                        "O" => server_cert.organization = rdn_content,
                                        _ => {}
                                    }
                                }
                                Err(_e) => {
                                    return Err(Error::new(
                                        ErrorKind::Other,
                                        "Error converting Oid to Nid".to_string(),
                                    ))
                                }
                            }
                        }
                    }
                }
            }

            let cert = Cert {
                server: server_cert,
                intermediate: intermediate_cert,
            };

            Ok(cert)
        } else {
            Err(Error::new(
                ErrorKind::NotFound,
                "certificate not found".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_ssl_server_is_valid() {
        assert!(
            CheckSSL::from_domain_with_port("rust-lang.org", "443")
                .unwrap()
                .server
                .is_valid
        );
    }

    #[test]
    fn test_check_ssl_server_is_invalid() {
        let actual =
            CheckSSL::from_domain_with_port("expired.badssl.com", "443").map_err(|e| e.kind());
        let expected = Err(ErrorKind::InvalidData);

        assert_eq!(expected, actual);
    }
}
