//! hq-interop: HTTP/0.9 over QUIC, as the interop runner's implementations
//! speak it.
//!
//! There is no specification; this follows the runner's documentation and
//! the reference implementations. Each request is a client-initiated
//! bidirectional stream on which the client writes `GET /<path>\r\n` and
//! ends its direction; the server answers on the same stream with the raw
//! bytes of the file and ends its own.

use std::path::{Component, Path, PathBuf};

use snafu::{OptionExt as _, Snafu, ensure};

/// The ALPN protocol name.
pub const ALPN: &[u8] = b"hq-interop";

/// The longest request the server reads.
pub const MAX_REQUEST: usize = 4096;

/// One URL of the client's `REQUESTS`: `https://<host>:<port>/<path>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    /// The host name or address, without the brackets of an IPv6 literal.
    pub host: String,
    /// The port, 443 when the URL gives none.
    pub port: u16,
    /// The path, starting with `/`.
    pub path: String,
}

/// A URL of `REQUESTS` is not one the client can fetch.
#[derive(Debug, Snafu)]
#[snafu(display("{url:?} is not an https URL with a host and a path"))]
pub struct UrlError {
    url: String,
}

impl Url {
    /// Reads `url`.
    ///
    /// # Errors
    ///
    /// [`UrlError`] when it is not `https://host[:port]/path`.
    pub fn parse(url: &str) -> Result<Self, UrlError> {
        let error = || UrlSnafu { url };
        let rest = url.strip_prefix("https://").with_context(error)?;
        let slash = rest.find('/').with_context(error)?;
        let (authority, path) = rest.split_at(slash);
        let (host, port) = if let Some(literal) = authority.strip_prefix('[') {
            let (host, after) = literal.split_once(']').with_context(error)?;
            let port = match after {
                "" => None,
                _ => Some(after.strip_prefix(':').with_context(error)?),
            };
            (host, port)
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            }
        };
        let port = match port {
            Some(port) => port.parse().ok().with_context(error)?,
            None => 443,
        };
        ensure!(!host.is_empty(), error());
        Ok(Self {
            host: host.to_owned(),
            port,
            path: path.to_owned(),
        })
    }

    /// The request line for this URL.
    pub fn request(&self) -> Vec<u8> {
        format!("GET {}\r\n", self.path).into_bytes()
    }

    /// The name the response is saved under: the path without its leading
    /// `/`, or `None` when it would leave the download directory.
    pub fn file_name(&self) -> Option<PathBuf> {
        relative(&self.path)
    }
}

/// A request the server cannot answer.
#[derive(Debug, Snafu)]
pub enum RequestError {
    /// The request is not `GET /<path>`.
    #[snafu(display("the request is not GET /<path>"))]
    Malformed,
    /// The path leaves the served directory.
    #[snafu(display("the path {path:?} leaves the served directory"))]
    Outside {
        /// The path asked for.
        path: String,
    },
}

/// The file under the served directory that `request` asks for, relative
/// to that directory. Trailing white space, the `\r\n` among it, is
/// ignored, as quic-go does.
///
/// # Errors
///
/// [`RequestError`].
pub fn requested_file(request: &[u8]) -> Result<PathBuf, RequestError> {
    let request = core::str::from_utf8(request).map_err(|_| RequestError::Malformed)?;
    let path = request
        .trim_end()
        .strip_prefix("GET ")
        .filter(|path| path.starts_with('/'))
        .context(MalformedSnafu)?;
    relative(path).context(OutsideSnafu { path })
}

/// `path`, which starts with `/`, as a path relative to a directory, when
/// it names something below it.
fn relative(path: &str) -> Option<PathBuf> {
    let relative = Path::new(path.strip_prefix('/')?);
    let mut out = PathBuf::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_has_a_host_a_port_and_a_path() {
        assert_eq!(
            Url::parse("https://server4:443/abc.bin").unwrap(),
            Url {
                host: "server4".into(),
                port: 443,
                path: "/abc.bin".into()
            }
        );
        assert_eq!(
            Url::parse("https://[fd00::1]:4433/x").unwrap(),
            Url {
                host: "fd00::1".into(),
                port: 4433,
                path: "/x".into()
            }
        );
        assert_eq!(Url::parse("https://server/x").unwrap().port, 443);
    }

    #[test]
    fn urls_without_https_a_host_or_a_path_are_refused() {
        for url in [
            "http://server/x",
            "https://server",
            "https:///x",
            "https://server:port/x",
            "https://[fd00::1/x",
        ] {
            assert!(Url::parse(url).is_err(), "{url}");
        }
    }

    #[test]
    fn a_request_is_get_and_the_path() {
        let url = Url::parse("https://server:443/a/b.bin").unwrap();
        assert_eq!(url.request(), b"GET /a/b.bin\r\n");
        assert_eq!(url.file_name().unwrap(), Path::new("a/b.bin"));
        assert_eq!(
            requested_file(&url.request()).unwrap(),
            Path::new("a/b.bin")
        );
    }

    #[test]
    fn requests_outside_the_directory_or_not_get_are_refused() {
        assert!(matches!(
            requested_file(b"GET /../etc/passwd\r\n"),
            Err(RequestError::Outside { .. })
        ));
        assert!(matches!(
            requested_file(b"GET /\r\n"),
            Err(RequestError::Outside { .. })
        ));
        assert!(matches!(
            requested_file(b"PUT /x\r\n"),
            Err(RequestError::Malformed)
        ));
        assert!(matches!(
            requested_file(b"GET x\r\n"),
            Err(RequestError::Malformed)
        ));
        assert!(matches!(
            requested_file(&[0xff]),
            Err(RequestError::Malformed)
        ));
    }
}
