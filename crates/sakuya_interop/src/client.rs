//! The hq-interop client: fetches the URLs of `REQUESTS` into
//! `/downloads`.

use core::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
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
use nitori_io::{ReadChunkHostExt as _, calls::WriteAllHostExt as _};
use sakuya_connection::prelude::*;
use sakuya_endpoint::{config::BindingDeclarations, endpoint::Endpoint, role::NoServer};
use sakuya_tls::client::ServerTarget;

use crate::{
    composition::{
        Client, ClientStarts, HqClose, OptionalKeyLog, bind, cipher_suites, client_config,
        endpoint_config,
    },
    environment::{ClientTestCase, Environment, UNSUPPORTED},
    hq::Url,
};

/// Where the runner wants the files.
const DOWNLOADS: &str = "/downloads";
/// Where the runner puts the certificates.
const CERTS: &str = "/certs";
/// How long a connection may take for its handshake, and after its
/// requests to end.
const STEP: Duration = Duration::from_secs(10);
/// How long all of a connection's requests may take.
const TRANSFER: Duration = Duration::from_secs(120);

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
    if let Some(dir) = &environment.qlog_dir {
        eprintln!(
            "sakuya client: QLOGDIR {} is set; no qlog is written yet",
            dir.display()
        );
    }
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
    let starts = match ClientStarts::load(
        Path::new(CERTS),
        cipher_suites(test_case == ClientTestCase::ChaCha20),
        key_log,
    ) {
        Ok(starts) => starts,
        Err(error) => {
            eprintln!("sakuya client: {}", crate::report(&error));
            return ExitCode::FAILURE;
        }
    };
    let batches: Vec<Vec<Url>> = match test_case {
        ClientTestCase::ConnectionPerRequest => environment
            .requests
            .into_iter()
            .map(|url| vec![url])
            .collect(),
        ClientTestCase::OneConnection | ClientTestCase::ChaCha20 => vec![environment.requests],
    };
    crate::run_local(fetch_all(starts, batches))
}

/// A failure of the client, already reported.
struct Failed;

async fn fetch_all(starts: ClientStarts, batches: Vec<Vec<Url>>) -> ExitCode {
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
    let local = match server {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let (client, reflow) =
        match Endpoint::<_, NoServer, Client>::new(endpoint_config((), client_config(starts))) {
            Ok(made) => made,
            Err(error) => {
                eprintln!(
                    "sakuya client: the endpoint cannot be made: {}",
                    crate::report(&error)
                );
                return ExitCode::FAILURE;
            }
        };
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
    let driver = tokio::task::spawn_local(driver);
    let mut outcome = ExitCode::SUCCESS;
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
        let (connection, handle) = match outgoing.start() {
            Ok(started) => started,
            Err(error) => {
                eprintln!(
                    "sakuya client: connection {number} cannot start: {}",
                    crate::report(&error)
                );
                outcome = ExitCode::FAILURE;
                break;
            }
        };
        let mut connection = tokio::task::spawn_local(connection);
        eprintln!("sakuya client: connection {number} to {server} started");
        let layer = match tokio::time::timeout(STEP, handle.established()).await {
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
                eprintln!("sakuya client: connection {number} is not established within {STEP:?}");
                handle.close(HqClose(0));
                outcome = ExitCode::FAILURE;
                break;
            }
        };
        eprintln!("sakuya client: connection {number} is established");
        let fetches = urls.iter().map(|url| {
            let layer = &layer;
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
                Ok(())
                }
                .await;
                if result.is_err() {
                    eprintln!("sakuya client: {} failed", url.path);
                }
                result
            }
        });
        let fetched = tokio::time::timeout(TRANSFER, join_all(fetches)).await;
        let all_fetched = match fetched {
            Ok(results) => results.iter().all(Result::is_ok),
            Err(_) => {
                eprintln!(
                    "sakuya client: connection {number}: requests not done within {TRANSFER:?}"
                );
                false
            }
        };
        handle.close(HqClose(0));
        match tokio::time::timeout(STEP, &mut connection).await {
            Ok(_) => eprintln!("sakuya client: connection {number} ended"),
            Err(_) => {
                eprintln!("sakuya client: connection {number} does not end within {STEP:?}");
                connection.abort();
            }
        }
        if !all_fetched {
            outcome = ExitCode::FAILURE;
            break;
        }
    }
    drop(binding);
    client.close();
    for (name, task) in [("binding driver", driver), ("reflow driver", reflow)] {
        if tokio::time::timeout(STEP, task).await.is_err() {
            eprintln!("sakuya client: the {name} does not end within {STEP:?}");
        }
    }
    outcome
}
