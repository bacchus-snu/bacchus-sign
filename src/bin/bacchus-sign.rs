#[macro_use]
extern crate log;

use std::path::PathBuf;
use std::sync::Arc;

use libsystemd::daemon::{notify as sd_notify, NotifyState};

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("systemd error")]
    Systemd(#[from] libsystemd::errors::SdError),
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("Failed to load keypair {}: {error}", .path.to_string_lossy())]
    Keypair {
        path: PathBuf,
        #[source]
        error: std::io::Error,
    },
    #[error("cannot find listen socket, run with systemd socket activation")]
    ListenSocketNotFound,
}

async fn run() -> Result<(), Error> {
    use libsystemd::activation::IsType;
    use tokio::io::AsyncReadExt;

    let keypath: PathBuf = std::env::args_os()
        .nth(1)
        .unwrap_or_else(|| std::ffi::OsString::from("/etc/bacchus/keypair/tweetnacl"))
        .into();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    sd_notify(false, &[NotifyState::Status(String::from("Loading keys"))])?;

    let mut private_key = [0u8; 64];
    tokio::fs::File::open(&keypath)
        .await
        .map_err(|error| Error::Keypair {
            path: keypath.clone(),
            error,
        })?
        .read_exact(&mut private_key)
        .await
        .map_err(|error| Error::Keypair {
            path: keypath.clone(),
            error,
        })?;
    let private_key = Arc::new(private_key);

    let fds = libsystemd::activation::receive_descriptors(true)?;
    let listen_fd = fds
        .into_iter()
        .find(|fd| fd.is_unix())
        .ok_or(Error::ListenSocketNotFound)?;
    let listen_fd = std::os::unix::io::IntoRawFd::into_raw_fd(listen_fd);
    // SAFETY: unix socket passed by systemd, envs are cleared
    let listen_socket = unsafe {
        <std::os::unix::net::UnixListener as std::os::unix::io::FromRawFd>::from_raw_fd(listen_fd)
    };
    listen_socket.set_nonblocking(true)?;
    let listen_socket = tokio::net::UnixListener::from_std(listen_socket)?;

    sd_notify(
        false,
        &[
            NotifyState::Ready,
            NotifyState::Status(String::from("Listening for connections")),
        ],
    )?;
    info!("Start accepting connections");
    loop {
        tokio::select! {
            sock = listen_socket.accept() => {
                let (conn, _) = sock?;
                tokio::spawn(run_connection(conn, private_key.clone()));
            },
            _ = sigterm.recv() => {
                break;
            },
        }
    }

    sd_notify(
        false,
        &[
            NotifyState::Stopping,
            NotifyState::Status(String::from("Terminating")),
        ],
    )?;
    info!("SIGTERM received, terminating");
    Ok(())
}

async fn run_connection(conn: tokio::net::UnixStream, private_key: Arc<[u8; 64]>) {
    if let Err(e) = run_connection_inner(conn, private_key).await {
        error!("Worker exited unsuccessfully: {}. Details: {:?}", e, e);
    }
}

async fn run_connection_inner(
    mut conn: tokio::net::UnixStream,
    private_key: Arc<[u8; 64]>,
) -> Result<(), Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut message_body = Vec::new();
    conn.read_to_end(&mut message_body).await?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::new(0, 0))
        .as_secs()
        .to_string();
    info!("Message received, timestamp: {}", timestamp);
    let mut message = timestamp.as_bytes().to_vec();
    message.extend(message_body);

    let mut out = vec![0u8; message.len() + 64];
    tweetnacl::sign(&mut out, &message, &private_key);

    let mut send_buf = String::new();
    base64::encode_config_buf(&private_key[32..], base64::STANDARD, &mut send_buf);
    send_buf.push('\n');
    send_buf.push_str(&timestamp);
    send_buf.push('\n');
    base64::encode_config_buf(&out[..64], base64::STANDARD, &mut send_buf);
    send_buf.push('\n');

    conn.write_all(send_buf.as_bytes()).await?;
    conn.shutdown().await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    sd_notify(
        false,
        &[NotifyState::Status(String::from("Setting up syslog"))],
    )?;

    let formatter = syslog::Formatter3164 {
        facility: syslog::Facility::LOG_USER,
        hostname: None,
        process: String::from("bacchus-sign"),
        pid: 0,
    };
    let log = syslog::unix(formatter)?;
    log::set_boxed_logger(Box::new(syslog::BasicLogger::new(log)))?;
    log::set_max_level(log::LevelFilter::Info);

    if let Err(e) = run().await {
        error!("Main loop exited unsuccessfully: {}. Details: {:?}", e, e);
        let errno = match &e {
            Error::Io(e) => e.raw_os_error(),
            Error::Systemd(_) => None,
            Error::Keypair { error: e, .. } => e.raw_os_error(),
            Error::ListenSocketNotFound => Some(2), // ENOENT
        };
        if let Some(e) = errno {
            sd_notify(false, &[NotifyState::Errno(e as u8)])?;
        }
        sd_notify(false, &[NotifyState::Status(e.to_string())])?;
        std::process::exit(1);
    }

    sd_notify(false, &[NotifyState::Status(String::from("Terminated"))])?;
    Ok(())
}
