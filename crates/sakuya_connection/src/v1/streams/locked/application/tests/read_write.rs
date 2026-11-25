//! The handles as nitori_io's `Read` and `Write`: segments without metadata
//! or reports, and `None` where no bytes move.

use nitori_io::{ReadHostExt as _, WriteHostExt as _};

use super::*;

/// A reader reads segments without metadata: none for no room, the data,
/// then none at the end of the stream.
#[test]
fn a_reader_reports_no_progress_and_the_end_as_none() {
    let (mut set, layer, _intake, mut publish) = client(100, 1000);
    lent(&mut set)
        .on_stream_frame(&mut publish, EncryptionLevel::OneRtt, fin_frame(1, 0, 5))
        .expect("taken");
    let (_writer, mut reader) = now(layer.accept_bi()).expect("stream 1");
    let mut room: &mut [u8] = &mut [];
    assert_eq!(
        now(reader.read_unpin(&mut room)).expect("read"),
        None,
        "no room"
    );
    let mut data = Vec::new();
    let segment = now(reader.read_unpin(&mut data))
        .expect("read")
        .expect("data");
    assert_eq!((segment.count.get(), data), (5, vec![7; 5]));
    let mut rest = Vec::new();
    assert_eq!(
        now(reader.read_unpin(&mut rest)).expect("read"),
        None,
        "the end"
    );
}

/// A writer takes no bytes from an empty input, and a segment of every byte
/// it takes otherwise.
#[test]
fn a_writer_reports_an_empty_input_as_none() {
    let (_set, layer, _intake, _publish) = client(100, 1000);
    let (writer, _reader) = layer.try_open_bi().expect("a stream");
    let mut writer = writer.with_send_options(Urgency::default(), AnyActiveLinkPath);
    assert_eq!(
        now(writer.write_unpin(&mut Bytes::new())).expect("write"),
        None
    );
    let mut input = Bytes::from(vec![1; 10]);
    let segment = now(writer.write_unpin(&mut input))
        .expect("write")
        .expect("taken");
    assert_eq!(segment.count.get(), 10);
    assert!(input.is_empty());
}
