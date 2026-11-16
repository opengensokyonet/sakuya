//! The hq-interop server: serves the files under `/www` on port 443 until
//! it is stopped.

use core::{net::SocketAddr, num::NonZeroUsize};
use std::{path::Path, process::ExitCode, rc::Rc};

use bytes::Bytes;
use futures_util::StreamExt as _;
use nitori_io::{ReadChunkHostExt as _, calls::WriteAllHostExt as _};
use sakuya_connection::prelude::*;
use sakuya_endpoint::{
    config::BindingDeclarations, endpoint::Endpoint, incoming::Incoming, role::NoClient,
};
use sakuya_wire::{v1::application_error::ApplicationErrorCode, var_int::VarInt};

use crate::{
    composition::{
        OptionalKeyLog, Server, ServerStarts, bind, cipher_suites, endpoint_config, server_config,
    },
    environment::{Environment, ServerTestCase, UNSUPPORTED},
    hq,
};

/// Where the runner puts the files to serve.
const WWW: &str = "/www";
/// Where the runner puts the certificates.
const CERTS: &str = "/certs";
/// The port the runner's clients connect to.
const PORT: u16 = 443;
/// How much of a file is read and written at once.
const CHUNK: usize = 64 * 1024;
/// How long the server waits for a connection's close reason after it ended.
const REASON_WAIT: core::time::Duration = core::time::Duration::from_millis(100);
/// The code a stream is reset with when its request cannot be answered.
const REFUSED: u32 = 0x10;

/// Runs the server in the environment the runner gives.
pub fn main() -> ExitCode {
    let environment = match Environment::read() {
        Ok(environment) => environment,
        Err(error) => {
            eprintln!("sakuya server: {}", crate::report(&error));
            return ExitCode::FAILURE;
        }
    };
    let Some(test_case) = ServerTestCase::from_name(&environment.test_case) else {
        eprintln!(
            "sakuya server: test case {:?} is not supported",
            environment.test_case
        );
        return ExitCode::from(UNSUPPORTED);
    };
    if let Some(dir) = &environment.qlog_dir {
        eprintln!(
            "sakuya server: QLOGDIR {} is set; no qlog is written yet",
            dir.display()
        );
    }
    let key_log = match OptionalKeyLog::open(environment.key_log.as_deref()) {
        Ok(key_log) => key_log,
        Err(error) => {
            eprintln!("sakuya server: the key log cannot be opened: {error}");
            return ExitCode::FAILURE;
        }
    };
    let starts = match ServerStarts::load(
        Path::new(CERTS),
        cipher_suites(test_case == ServerTestCase::ChaCha20),
        key_log,
    ) {
        Ok(starts) => starts,
        Err(error) => {
            eprintln!("sakuya server: {}", crate::report(&error));
            return ExitCode::FAILURE;
        }
    };
    crate::run_local(serve(starts, test_case == ServerTestCase::Retry))
}

async fn serve(starts: ServerStarts, always_retry: bool) -> ExitCode {
    let (server, reflow) = match Endpoint::<_, Server, NoClient>::new(endpoint_config(
        server_config(starts, always_retry),
        (),
    )) {
        Ok(made) => made,
        Err(error) => {
            eprintln!(
                "sakuya server: the endpoint cannot be made: {}",
                crate::report(&error)
            );
            return ExitCode::FAILURE;
        }
    };
    crate::assert_send(&reflow);
    tokio::task::spawn_local(reflow);
    let address = SocketAddr::from((core::net::Ipv6Addr::UNSPECIFIED, PORT));
    let socket = match bind(address) {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!(
                "sakuya server: cannot bind {address}: {}",
                crate::report(&error)
            );
            return ExitCode::FAILURE;
        }
    };
    let (_binding, driver) =
        match server.add_accepting_binding(socket, BindingDeclarations::default()) {
            Ok(added) => added,
            Err(error) => {
                eprintln!(
                    "sakuya server: the binding cannot be added: {}",
                    crate::report(&error)
                );
                return ExitCode::FAILURE;
            }
        };
    crate::assert_send(&driver);
    tokio::task::spawn_local(driver);
    eprintln!("sakuya server: listening on {address}");
    let www: Rc<Path> = Path::new(WWW).into();
    let mut incoming = server.incoming();
    let mut count = 0_u64;
    while let Some(Incoming::Terminable(half)) = incoming.next().await {
        count += 1;
        let number = count;
        let facts = half.facts().clone();
        let peer = facts.peer;
        let (connection, handle) = match half.accept() {
            Ok(accepted) => accepted,
            Err(error) => {
                eprintln!(
                    "sakuya server: connection {number} from {peer:?} cannot be accepted: {}",
                    crate::report(&error)
                );
                continue;
            }
        };
        eprintln!("sakuya server: connection {number}: {facts:?}");
        crate::assert_send(&connection);
        let ended = tokio::task::spawn_local(connection);
        let watched = handle.clone();
        tokio::task::spawn_local(async move {
            match ended.await {
                Ok(()) => eprintln!("sakuya server: connection {number} ended"),
                Err(error) => eprintln!("sakuya server: connection {number} panicked: {error}"),
            }
            // `closed` may stay pending when the connection ended where it
            // recorded its reason (sakuya main 8878066), so it is not waited
            // for long
            match tokio::time::timeout(REASON_WAIT, watched.closed()).await {
                Ok(reason) => eprintln!("sakuya server: connection {number} closed: {reason:?}"),
                Err(_) => eprintln!("sakuya server: connection {number}: no close reason"),
            }
        });
        let www = Rc::clone(&www);
        tokio::task::spawn_local(async move {
            let layer = match handle.established().await {
                Ok(layer) => layer,
                Err(error) => {
                    eprintln!(
                        "sakuya server: connection {number} is not established: {}",
                        crate::report(&error)
                    );
                    return;
                }
            };
            eprintln!("sakuya server: connection {number} is established");
            let reason = loop {
                match layer.accept_bi().await {
                    Ok((writer, reader)) => {
                        let www = Rc::clone(&www);
                        let (mut writer, mut reader) = (writer, reader);
                        tokio::task::spawn_local(async move {
                            let mut request = Vec::new();
                            loop {
                                match reader
                                    .read_chunk_unpin(
                                        NonZeroUsize::new(hq::MAX_REQUEST).expect("not zero"),
                                    )
                                    .await
                                {
                                    Ok(Some(chunk)) => {
                                        request.extend_from_slice(&chunk);
                                        if request.len() > hq::MAX_REQUEST {
                                            eprintln!(
                                                "sakuya server: connection {number}: a request is too long"
                                            );
                                            let _ = writer.reset(code(REFUSED));
                                            return;
                                        }
                                    }
                                    Ok(None) => break,
                                    Err(error) => {
                                        eprintln!(
                                            "sakuya server: connection {number}: a request cannot be read: {}",
                                            crate::report(&error),
                                        );
                                        return;
                                    }
                                }
                            }
                            let file = match hq::requested_file(&request) {
                                Ok(file) => www.join(file),
                                Err(error) => {
                                    eprintln!(
                                        "sakuya server: connection {number}: {}",
                                        crate::report(&error)
                                    );
                                    let _ = writer.reset(code(REFUSED));
                                    return;
                                }
                            };
                            let content = match std::fs::read(&file) {
                                Ok(content) => Bytes::from(content),
                                Err(error) => {
                                    eprintln!(
                                        "sakuya server: connection {number}: {} cannot be read: {error}",
                                        file.display()
                                    );
                                    let _ = writer.reset(code(REFUSED));
                                    return;
                                }
                            };
                            let mut rest = content;
                            while !rest.is_empty() {
                                let chunk = rest.split_to(rest.len().min(CHUNK));
                                if let Err(error) = writer.write_all_unpin(chunk).await {
                                    eprintln!(
                                        "sakuya server: connection {number}: {} cannot be sent: {}",
                                        file.display(),
                                        crate::report(&error),
                                    );
                                    return;
                                }
                            }
                            if let Err(error) = writer.close() {
                                eprintln!(
                                    "sakuya server: connection {number}: the answer cannot end: {}",
                                    crate::report(&error),
                                );
                            }
                        });
                    }
                    Err(end) => break end,
                }
            };
            eprintln!("sakuya server: connection {number} takes no more streams: {reason:?}");
        });
    }
    eprintln!("sakuya server: the endpoint takes no more connections");
    ExitCode::SUCCESS
}

fn code(code: u32) -> ApplicationErrorCode {
    ApplicationErrorCode::new(VarInt::from_u32(code))
}
