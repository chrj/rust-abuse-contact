//! Error types for the crate.

/// A value that cannot be used as a query or as a result.
///
/// These come from the constructors of the newtypes in this crate. A lookup that is
/// certain to fail never reaches the network, and a placeholder a registry sends in
/// place of a real address never reaches the caller.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ValidationError {
    /// The domain name was empty.
    #[error("the domain name is empty. Give a name such as \"example.com\"")]
    EmptyDomain,

    /// The domain name was not shaped like a domain name.
    #[error("\"{value}\" is not a domain name: {problem}")]
    InvalidDomain {
        /// The rejected value.
        value: String,
        /// What is wrong with it.
        problem: &'static str,
    },

    /// The email address was not shaped like an email address.
    #[error("\"{value}\" is not an email address: {problem}")]
    InvalidEmail {
        /// The rejected value.
        value: String,
        /// What is wrong with it.
        problem: &'static str,
    },

    /// A source sent a fixed address that stands for "no contact published".
    ///
    /// A regional registry that withholds the contact of a network answers with one
    /// address for every network in the region. The address is a marker, not a
    /// mailbox that reads reports.
    #[error(
        "\"{value}\" is the address a source returns when it has no contact for the \
         network, not a contact. Ask the regional registry, or use the technical \
         contact from RDAP"
    )]
    WithheldEmail {
        /// The marker the source sent.
        value: String,
    },

    /// The registry sent a placeholder in place of an address.
    ///
    /// A registry that hides contact data puts a fixed string such as
    /// `DATA REDACTED` in the field. The string is not an address and must not be
    /// used as one.
    #[error(
        "\"{value}\" is a placeholder the registry sends in place of an address, \
         not an address. Look for the abuse contact of the network instead"
    )]
    RedactedEmail {
        /// The placeholder the registry sent.
        value: String,
    },
}

/// A lookup that did not finish.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The request did not complete: DNS, TLS, connection or timeout.
    #[error("the request to {server} did not complete: {source}")]
    Transport {
        /// The server the request went to.
        server: String,
        /// What the HTTP layer reported.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The body was not the RDAP this crate expects.
    #[error("{server} answered with a body that is not RDAP: {source}")]
    Decode {
        /// The server that answered.
        server: String,
        /// What the reader reported.
        #[source]
        source: serde_json::Error,
    },

    /// The server answered, and the answer was not a record.
    #[error("{server} answered {status} for {target}")]
    Status {
        /// The server that answered.
        server: String,
        /// The HTTP status it sent.
        status: u16,
        /// What was asked about.
        target: String,
    },

    /// The server sent a body longer than the crate reads.
    ///
    /// A record is a few kilobytes. A body past the limit is a fault on the server, or
    /// a server that tries to use up the memory of the process.
    #[error("{server} sent a body longer than {limit} bytes, which is more than a record")]
    TooLarge {
        /// The server that answered.
        server: String,
        /// The most the crate reads, in bytes.
        limit: usize,
    },

    /// No registry holds the address or the name.
    ///
    /// The bootstrap registry names a server for every range IANA has given out. A
    /// target with no server is a private address, a reserved range, or a name under
    /// a top-level domain that runs no RDAP server.
    #[error(
        "no RDAP server answers for {target}. Check that it is a public address or a \
         registered name, and not a private or reserved range"
    )]
    NoServer {
        /// What was asked about.
        target: String,
    },

    /// The address is not one the public registries describe.
    ///
    /// A regional registry holds a record for the reserved block a private address
    /// sits in, and that record names IANA. Answering with it gives a contact that
    /// cannot act, so the lookup stops here instead.
    #[error(
        "{target} is a private, reserved or documentation address. The registries \
         describe the reserved block, not the host, so a report about it has no \
         owner. Use the public address that carried the traffic"
    )]
    NotPublic {
        /// The address that was asked about.
        target: String,
    },

    /// A value did not satisfy a documented limit.
    #[error(transparent)]
    Validation(#[from] ValidationError),
}
