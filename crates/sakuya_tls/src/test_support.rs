//! Building encodings by hand for tests of the readers.

/// A handshake message of type `message_type` with `body`.
pub(crate) fn message(message_type: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![message_type];
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    bytes.extend_from_slice(body);
    bytes
}

/// An extension of type `extension_type` with `data`.
pub(crate) fn extension(extension_type: u16, data: &[u8]) -> Vec<u8> {
    let mut bytes = extension_type.to_be_bytes().to_vec();
    bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
    bytes.extend_from_slice(data);
    bytes
}

/// `items` with a length field of `width` bytes.
pub(crate) fn vector(width: usize, items: &[u8]) -> Vec<u8> {
    let mut bytes = (items.len() as u32).to_be_bytes()[4 - width..].to_vec();
    bytes.extend_from_slice(items);
    bytes
}

/// The concatenation of `parts`.
pub(crate) fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// supported_versions data of a ClientHello offering TLS 1.3 and 1.2.
pub(crate) const VERSIONS: &[u8] = &[0x04, 0x03, 0x04, 0x03, 0x03];

/// The body of a ClientHello with the extension block `extensions`, given
/// without its length field.
pub(crate) fn client_hello_body(
    session_id: &[u8],
    suites: &[u8],
    compression: &[u8],
    extensions: &[u8],
) -> Vec<u8> {
    concat(&[
        &[0x03, 0x03],
        &[0x11; 32],
        &vector(1, session_id),
        &vector(2, suites),
        &vector(1, compression),
        &vector(2, extensions),
    ])
}

/// A ClientHello message with the extension block `extensions`.
pub(crate) fn client_hello(extensions: &[u8]) -> Vec<u8> {
    message(1, &client_hello_body(&[], &[0x13, 0x01], &[0], extensions))
}
