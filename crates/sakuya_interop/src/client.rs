//! The hq-interop client: fetches the URLs of `REQUESTS` into
//! `/downloads`.
//!
//! Under `datagram` it fetches nothing: it sends datagrams to the server
//! of the first URL and waits for each to come back,
//! writing what came back to `/downloads/datagram.txt`. Under
//! `resetstreamat` an answer may end with a reset: what was read of it is
//! saved, and how it ended is written to the file's name with `.end`
//! added.

use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroUsize,
    time::Duration,
};
use std::{
    io::Write as _,
    net::ToSocketAddrs as _,
    path::{Path, PathBuf},
    process::ExitCode,
};

use bytes::Bytes;
use futures_util::future::join_all;
use kasen_handshake::client::ServerTarget;
use nitori_io::{ReadChunkHostExt as _, calls::WriteAllHostExt as _};
use sakuya_connection::prelude::*;
use sakuya_connection::{
    shared::SharedConnectionDriver, v1::application_handles::connection::ConnectionHandle,
};
use sakuya_connection_datagram::application::Datagrams as _;
use sakuya_endpoint_v1::{config::BindingDeclarations, endpoint::Endpoint, role::NoServer};
use sakuya_stream_v1::connection::LayerEnd;
use sakuya_stream_v1::receive::read::ReadError;
use sakuya_sync_std::MutexSharedConnection;

use crate::{
    composition::{
        Client, ClientStarts, Extensions, HqClose, OptionalKeyLog, bind, cipher_suites,
        client_config, endpoint_config,
    },
    environment::{ClientTestCase, Environment, UNSUPPORTED},
    hq::Url,
};

/// Where the runner wants the files.
const DOWNLOADS: &str = "/downloads";
/// Where the runner puts the certificates.
/// How long a connection may take to get a link, and how long the
/// connections still closing and the drivers may take to end once every
/// request is done.
const STEP: Duration = Duration::from_secs(10);
/// How long a connection may take for its handshake: longer than the idle
/// timeout the client declares, so that while packets keep arriving under
/// heavy loss the connection's own idle timeout decides, not this bound.
const HANDSHAKE: Duration = Duration::from_secs(60);
/// How long all of a connection's requests may take.
const TRANSFER: Duration = Duration::from_secs(120);
mod datagrams;

/// Under `datagram`: exchanges datagrams on the established layer
/// `$layer` of connection `$number` ([`datagrams::exchange`]), and tells
/// whether every one came back.
macro_rules! exchange_datagrams {
    ($layer:expr, $number:expr) => {{
        use bytes::Buf as _;
        use datagrams::Sending;
        use sakuya_connection_datagram::application::SendDatagramError;
        let writer = $layer.datagram_writer();
        let limits = writer.datagram_limits();
        eprintln!(
            "sakuya client: connection {}: datagram limits {limits:?}",
            $number
        );
        let layer = &$layer;
        datagrams::exchange(
            limits.guaranteed,
            |payload| match writer.send(payload) {
                Ok(ticket) => {
                    ticket.release();
                    Sending::Taken
                }
                Err(SendDatagramError::QueueFull) => Sending::Full,
                Err(error) => Sending::Refused(crate::report(&error)),
            },
            move || async move {
                let mut datagram = layer.recv_datagram().await.ok()?;
                Some(datagram.copy_to_bytes(datagram.remaining()))
            },
        )
        .await
        .is_ok()
    }};
}

/// Runs the client in the environment the runner gives.
pub fn main() -> ExitCode {
    let environment = match Environment::read() {
        Ok(environment) => environment,
        Err(error) => {
            eprintln!("sakuya client: {}", crate::report(&error));
            return ExitCode::FAILURE;
        }
    };
    let Some(test_case) = ClientTestCase::from_name(&environment.test_case) else {
        eprintln!(
            "sakuya client: test case {:?} is not supported",
            environment.test_case
        );
        return ExitCode::from(UNSUPPORTED);
    };
    if environment.requests.is_empty() {
        eprintln!("sakuya client: REQUESTS is empty");
        return ExitCode::FAILURE;
    }
    let key_log = match OptionalKeyLog::open(environment.key_log.as_deref()) {
        Ok(key_log) => key_log,
        Err(error) => {
            eprintln!("sakuya client: the key log cannot be opened: {error}");
            return ExitCode::FAILURE;
        }
    };
    let starts = ClientStarts::new(
        cipher_suites(test_case == ClientTestCase::ChaCha20),
        key_log,
    );
    let batches: Vec<Vec<Url>> = match test_case {
        ClientTestCase::ConnectionPerRequest => environment
            .requests
            .into_iter()
            .map(|url| vec![url])
            .collect(),
        ClientTestCase::Resumption | ClientTestCase::ZeroRtt => {
            let mut requests = environment.requests;
            let rest = requests.split_off(1);
            [requests, rest]
                .into_iter()
                .filter(|batch| !batch.is_empty())
                .collect()
        }
        ClientTestCase::Datagram => vec![environment.requests.into_iter().take(1).collect()],
        ClientTestCase::OneConnection
        | ClientTestCase::ChaCha20
        | ClientTestCase::KeyUpdate
        | ClientTestCase::ResetStreamAt => vec![environment.requests],
    };
    crate::run_local(fetch_all(starts, test_case, batches, environment.qlog_dir))
}

/// A failure of the client, already reported.
struct Failed;

/// The local address the kernel sends to `peer` from.
fn route_source(peer: SocketAddr) -> std::io::Result<IpAddr> {
    let any = match peer {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let probe = std::net::UdpSocket::bind(SocketAddr::new(any, 0))?;
    probe.connect(peer)?;
    Ok(probe.local_addr()?.ip())
}

async fn fetch_all(
    starts: ClientStarts,
    test_case: ClientTestCase,
    batches: Vec<Vec<Url>>,
    qlog_dir: Option<PathBuf>,
) -> ExitCode {
    let extensions = Extensions {
        datagram: test_case == ClientTestCase::Datagram,
        reset_stream_at: test_case == ClientTestCase::ResetStreamAt,
    };
    let reset_at = extensions.reset_stream_at;
    let mut tickets_stored = starts.tickets_stored();
    let first = &batches[0][0];
    let server = match (first.host.as_str(), first.port).to_socket_addrs() {
        Ok(mut addresses) => match addresses.next() {
            Some(address) => address,
            None => {
                eprintln!("sakuya client: {} has no address", first.host);
                return ExitCode::FAILURE;
            }
        },
        Err(error) => {
            eprintln!("sakuya client: {} cannot be resolved: {error}", first.host);
            return ExitCode::FAILURE;
        }
    };
    // the address the route to the server leaves from, not the wildcard: a
    // binding that is exactly the local end of its links is one a
    // connection can take another link on, to a preferred address
    let local = match route_source(server) {
        Ok(ip) => SocketAddr::new(ip, 0),
        Err(error) => {
            eprintln!("sakuya client: no local address routes to {server}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let (client, reflow) = match Endpoint::<_, NoServer, Client>::new(endpoint_config(
        (),
        client_config(
            starts,
            extensions,
            test_case == ClientTestCase::KeyUpdate,
            qlog_dir,
        ),
    )) {
        Ok(made) => made,
        Err(error) => {
            eprintln!(
                "sakuya client: the endpoint cannot be made: {}",
                crate::report(&error)
            );
            return ExitCode::FAILURE;
        }
    };
    crate::assert_send(&reflow);
    let reflow = tokio::task::spawn_local(reflow);
    let socket = match bind(local) {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!(
                "sakuya client: cannot bind {local}: {}",
                crate::report(&error)
            );
            return ExitCode::FAILURE;
        }
    };
    let (binding, driver) =
        match client.add_connect_only_binding(socket, BindingDeclarations::default()) {
            Ok(added) => added,
            Err(error) => {
                eprintln!(
                    "sakuya client: the binding cannot be added: {}",
                    crate::report(&error)
                );
                return ExitCode::FAILURE;
            }
        };
    crate::assert_send(&driver);
    let driver = tokio::task::spawn_local(driver);
    let mut outcome = ExitCode::SUCCESS;
    // connections that were asked to close: their closing periods run while
    // the next connection is made, and are waited for at the end
    let mut closing = Vec::new();
    for (number, urls) in batches.iter().enumerate() {
        let number = number + 1;
        let host = &urls[0].host;
        let target = match ServerTarget::from_host_name(host) {
            Ok(target) => target,
            Err(error) => {
                eprintln!(
                    "sakuya client: {host} is not a server name: {}",
                    crate::report(&error)
                );
                outcome = ExitCode::FAILURE;
                break;
            }
        };
        let outgoing = match tokio::time::timeout(STEP, binding.connect(server, target)).await {
            Ok(Ok(outgoing)) => outgoing,
            Ok(Err(error)) => {
                eprintln!(
                    "sakuya client: connection {number} cannot get a link: {}",
                    crate::report(&error)
                );
                outcome = ExitCode::FAILURE;
                break;
            }
            Err(_) => {
                eprintln!("sakuya client: connection {number} gets no link within {STEP:?}");
                outcome = ExitCode::FAILURE;
                break;
            }
        };
        let connection = match outgoing.start() {
            Ok(started) => MutexSharedConnection::new(started),
            Err(error) => {
                eprintln!(
                    "sakuya client: connection {number} cannot start: {}",
                    crate::report(&error)
                );
                outcome = ExitCode::FAILURE;
                break;
            }
        };
        let handle = ConnectionHandle::new(connection.clone());
        let connection = SharedConnectionDriver::new(connection);
        crate::assert_send(&connection);
        let mut connection = tokio::task::spawn_local(connection);
        eprintln!("sakuya client: connection {number} to {server} started");
        // under zerortt the requests go in 0-RTT on the layer before the
        // handshake completes, when the connection has one: taking it asks
        // for 0-RTT (RFC 9001 §5.6)
        let early = if test_case == ClientTestCase::ZeroRtt {
            match tokio::time::timeout(HANDSHAKE, handle.early()).await {
                Ok(Ok(early)) => early,
                // the wait for the established layer reports it
                Ok(Err(_)) | Err(_) => None,
            }
        } else {
            None
        };
        let sends_early = early.is_some();
        if sends_early {
            eprintln!("sakuya client: connection {number} sends 0-RTT");
        }
        let established = async {
            match early {
                Some(early) => Ok(early),
                None => handle.established().await,
            }
        };
        let mut layer = match tokio::time::timeout(HANDSHAKE, established).await {
            Ok(Ok(layer)) => layer,
            Ok(Err(error)) => {
                eprintln!(
                    "sakuya client: connection {number} is not established: {}",
                    crate::report(&error)
                );
                if let Ok(reason) = tokio::time::timeout(STEP, handle.closed()).await {
                    eprintln!("sakuya client: connection {number} closed: {reason:?}");
                }
                outcome = ExitCode::FAILURE;
                break;
            }
            Err(_) => {
                eprintln!(
                    "sakuya client: connection {number} is not established within {HANDSHAKE:?}"
                );
                handle.close(HqClose(0));
                outcome = ExitCode::FAILURE;
                break;
            }
        };
        eprintln!("sakuya client: connection {number} is established");
        // the fetches of every URL on the layer `$layer`
        macro_rules! fetches {
            ($layer:ident) => {
        urls.iter().map(|url| {
            let layer = &$layer;
            async move {
                let result: Result<(), Failed> = async {
                let Some(name) = url.file_name() else {
                    eprintln!("sakuya client: {} names no file under the download directory", url.path);
                    return Err(Failed);
                };
                let path: PathBuf = Path::new(DOWNLOADS).join(name);
                let (mut writer, mut reader) = layer.open_bi().await.map_err(|error| {
                    eprintln!("sakuya client: no stream for {}: {}", url.path, crate::report(&error));
                    Failed
                })?;
                writer
                    .write_all_unpin(Bytes::from(url.request()))
                    .await
                    .map_err(|error| {
                        eprintln!("sakuya client: the request for {} cannot be sent: {}", url.path, crate::report(&error));
                        Failed
                    })?;
                writer.close().map_err(|error| {
                    eprintln!("sakuya client: the request for {} cannot end: {}", url.path, crate::report(&error));
                    Failed
                })?;
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let mut file = std::fs::File::create(&path).map_err(|error| {
                    eprintln!("sakuya client: {} cannot be created: {error}", path.display());
                    Failed
                })?;
                let mut received = 0_usize;
                loop {
                    match reader
                        .read_chunk_unpin(NonZeroUsize::new(64 * 1024).expect("not zero"))
                        .await
                    {
                        Ok(Some(chunk)) => {
                            received += chunk.len();
                            file.write_all(&chunk).map_err(|error| {
                                eprintln!("sakuya client: {} cannot be written: {error}", path.display());
                                Failed
                            })?;
                        }
                        Ok(None) => break,
                        Err(ReadError::Reset { reset, .. }) if reset_at => {
                            let end = format!(
                                "reset {} reliable_size {} final_size {} received {received}\n",
                                reset.code().get().get(),
                                reset.reliable_size().get(),
                                reset.final_size().get(),
                            );
                            eprintln!("sakuya client: {}: {}", url.path, end.trim_end());
                            return write_end(&path, &end);
                        }
                        Err(error) => {
                            eprintln!(
                                "sakuya client: the answer for {} cannot be read after {received} bytes: {}",
                                url.path,
                                crate::report(&error),
                            );
                            return Err(Failed);
                        }
                    }
                }
                eprintln!("sakuya client: {} done, {received} bytes", url.path);
                if reset_at {
                    return write_end(&path, &format!("fin received {received}\n"));
                }
                Ok(())
                }
                .await;
                if result.is_err() {
                    eprintln!("sakuya client: {} failed", url.path);
                }
                result
            }
        })
            };
        }
        let all_fetched = if test_case == ClientTestCase::Datagram {
            exchange_datagrams!(layer, number)
        } else {
            let fetched = tokio::time::timeout(TRANSFER, join_all(fetches!(layer))).await;
            match fetched {
                Ok(results) => results.iter().all(Result::is_ok),
                Err(_) => {
                    eprintln!(
                        "sakuya client: connection {number}: requests not done within {TRANSFER:?}"
                    );
                    false
                }
            }
        };
        // a rejected 0-RTT ended the early layer with its requests: they go
        // again on the layer built after the handshake (RFC 9001 §4.6.2)
        let rejected = sends_early
            && !all_fetched
            && matches!(
                tokio::time::timeout(STEP, layer.ended()).await,
                Ok(LayerEnd::ZeroRttRejected)
            );
        let all_fetched = if rejected {
            eprintln!("sakuya client: connection {number}: 0-RTT rejected, requests again");
            match tokio::time::timeout(HANDSHAKE, handle.established()).await {
                Ok(Ok(again)) => {
                    layer = again;
                    let fetched = tokio::time::timeout(TRANSFER, join_all(fetches!(layer))).await;
                    matches!(fetched, Ok(results) if results.iter().all(Result::is_ok))
                }
                Ok(Err(_)) | Err(_) => false,
            }
        } else {
            all_fetched
        };
        // the connection to resume from closes once a ticket is kept, which
        // the server sends after its handshake, before any answer
        if matches!(
            test_case,
            ClientTestCase::Resumption | ClientTestCase::ZeroRtt
        ) && number < batches.len()
            && all_fetched
        {
            let kept = tokio::time::timeout(STEP, tickets_stored.wait_for(|stored| *stored > 0));
            if !matches!(kept.await, Ok(Ok(_))) {
                eprintln!("sakuya client: connection {number} keeps no ticket within {STEP:?}");
                handle.close(HqClose(0));
                outcome = ExitCode::FAILURE;
                break;
            }
            eprintln!("sakuya client: connection {number} kept a ticket");
        }
        handle.close(HqClose(0));
        closing.push(async move {
            match tokio::time::timeout(STEP, &mut connection).await {
                Ok(_) => eprintln!("sakuya client: connection {number} ended"),
                Err(_) => {
                    eprintln!("sakuya client: connection {number} does not end within {STEP:?}");
                    connection.abort();
                }
            }
        });
        if !all_fetched {
            outcome = ExitCode::FAILURE;
            break;
        }
    }
    join_all(closing).await;
    drop(binding);
    client.close();
    for (name, task) in [("binding driver", driver), ("reflow driver", reflow)] {
        if tokio::time::timeout(STEP, task).await.is_err() {
            eprintln!("sakuya client: the {name} does not end within {STEP:?}");
        }
    }
    outcome
}

/// Writes how the answer saved at `path` ended next to it.
fn write_end(path: &Path, end: &str) -> Result<(), Failed> {
    let mut name = path.as_os_str().to_owned();
    name.push(".end");
    std::fs::write(&name, end).map_err(|error| {
        eprintln!(
            "sakuya client: {} cannot be written: {error}",
            Path::new(&name).display()
        );
        Failed
    })
}
