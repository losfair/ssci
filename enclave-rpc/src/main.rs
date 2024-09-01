use std::{
    net::{Ipv6Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    process::Stdio,
};

use anyhow::Context;
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use bytes::{Bytes, BytesMut};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use clap::Parser;
use futures::{Sink, SinkExt, Stream, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::codec::{Framed, FramedRead, FramedWrite, LengthDelimitedCodec};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY, VMADDR_CID_HYPERVISOR};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Enclave RPC service
#[derive(clap::Parser)]
struct Args {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Parser)]
enum Cmd {
    Host(HostArgs),
    Guest,
}

#[derive(clap::Parser)]
struct HostArgs {
    #[clap(long, env = "ENCLAVE_CID")]
    enclave_cid: u32,

    #[clap(long, env = "REKOR_LOG_INDEX", default_value = "0")]
    rekor_log_index: u32,
}

fn main() {
    if std::env::var("RUST_LOG").is_err() {
        unsafe {
            std::env::set_var("RUST_LOG", "info");
        }
    }

    tracing_subscriber::fmt::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let args = Args::parse();
    let ret = match args.cmd {
        Cmd::Host(args) => rt.block_on(async_main_outside_enclave(args)),
        Cmd::Guest => rt.block_on(async_main_in_enclave()),
    };
    if let Err(error) = ret {
        tracing::error!(?error, "exiting with error");
        std::process::exit(1);
    }
}

async fn async_main_outside_enclave(args: HostArgs) -> anyhow::Result<()> {
    tracing::info!("running outside enclave");

    let cid = args.enclave_cid;
    let rekor_log_index = args.rekor_log_index;

    let mut http_proxy = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, 1081))
        .with_context(|| "http proxy bind failed")?;
    tokio::spawn(async move {
        loop {
            let mut conn = http_proxy
                .accept()
                .await
                .expect("http proxy accept failed")
                .0;

            tokio::spawn(async move {
                let mut backend = match TcpStream::connect("127.0.0.1:1081").await {
                    Ok(backend) => backend,
                    Err(error) => {
                        tracing::error!(?error, "failed to connect to backend");
                        return;
                    }
                };
                if let Err(error) = tokio::io::copy_bidirectional(&mut conn, &mut backend).await {
                    tracing::error!(?error, "http proxy copy failed");
                }
            });
        }
    });

    let incoming = TcpListener::bind("0.0.0.0:8000")
        .await
        .with_context(|| "tcp bind failed")?;
    loop {
        let (conn, peer_addr) = incoming.accept().await?;
        tracing::info!(?peer_addr, "new connection");

        tokio::spawn(async move {
            let mut ws = match tokio_tungstenite::accept_async(conn).await {
                Ok(x) => x,
                Err(error) => {
                    tracing::error!(?error, "websocket accept failed");
                    return;
                }
            };
            let mut backend = match VsockStream::connect(VsockAddr::new(cid, 1)).await {
                Ok(x) => x,
                Err(error) => {
                    tracing::error!(?error, "vsock connect failed");
                    return;
                }
            };

            if ws
                .send(Message::Text(
                    serde_json::json!({
                        "rekorLogIndex": rekor_log_index,
                    })
                    .to_string(),
                ))
                .await
                .is_err()
            {
                return;
            }

            // handshake - 32 bytes in each direction
            let Some(Ok(Message::Binary(c2s_handshake))) = ws.next().await else {
                return;
            };
            if c2s_handshake.len() != 32 {
                tracing::error!("unexpected handshake size");
                return;
            }
            if backend.write_all(&c2s_handshake).await.is_err() {
                return;
            }
            let mut s2c_handshake = [0u8; 32];
            if backend.read_exact(&mut s2c_handshake).await.is_err() {
                return;
            }
            if ws
                .send(Message::Binary(s2c_handshake.to_vec()))
                .await
                .is_err()
            {
                return;
            }

            let (mut backend_tx, mut backend_rx) =
                Framed::new(backend, LengthDelimitedCodec::new()).split();
            let (mut ws_tx, mut ws_rx) = ws.split();
            let copy1 = async {
                while let Some(msg) = backend_rx.next().await {
                    let msg = msg?;
                    ws_tx.send(Message::Binary(msg.into())).await?;
                }
                Ok::<_, anyhow::Error>(())
            };
            let copy2 = async {
                while let Some(msg) = ws_rx.next().await {
                    let msg = msg?;
                    match msg {
                        Message::Binary(data) => {
                            backend_tx.send(Bytes::from(data)).await?;
                        }
                        _ => {}
                    }
                }
                Ok::<_, anyhow::Error>(())
            };
            let ret = tokio::select! {
                ret = copy1 => ret,
                ret = copy2 => ret,
            };
            if let Err(error) = ret {
                tracing::error!(?error, "websocket copy failed");
            }
        });
    }
}

async fn async_main_in_enclave() -> anyhow::Result<()> {
    tracing::info!("running as enclave init");

    // start lo interface using ifconfig
    let mut cmd = tokio::process::Command::new("/sbin/ifconfig")
        .arg("lo")
        .arg("127.0.0.1")
        .arg("up")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| "failed to start ifconfig (1)")?;
    let ret = cmd.wait().await;
    if !ret.unwrap().success() {
        anyhow::bail!("ifconfig failed");
    }

    let _ = tokio::process::Command::new("/sbin/ifconfig")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| "failed to start ifconfig (2)")?
        .wait()
        .await;

    let nsm_fd = aws_nitro_enclaves_nsm_api::driver::nsm_init();
    if nsm_fd < 0 {
        anyhow::bail!("Failed to initialize NSM");
    }

    let ret = tokio::process::Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-f")
        .arg("/opt/sshd/ssh_host_ed25519_key")
        .arg("-N")
        .arg("")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| "failed to run ssh-keygen")?
        .wait()
        .await
        .expect("ssh-keygen failed");
    if !ret.success() {
        anyhow::bail!("ssh-keygen failed with {:?}", ret);
    }

    std::fs::create_dir_all("/run/sshd").expect("failed to create /run/sshd");

    // start sshd
    let mut cmd = tokio::process::Command::new("/usr/sbin/sshd")
        .arg("-D")
        .arg("-e")
        .arg("-f")
        .arg("/opt/sshd/sshd_config")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| "failed to start sshd")?;
    tokio::spawn(async move {
        let ret = cmd.wait().await;
        panic!("sshd exited: {:?}", ret);
    });

    // start forwarding
    for port in [1081, 2049] {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .with_context(|| "proxy bind failed")?;
        tokio::spawn(async move {
            loop {
                let mut conn = listener.accept().await.expect("proxy accept failed").0;

                tokio::spawn(async move {
                    let mut backend =
                        match VsockStream::connect(VsockAddr::new(VMADDR_CID_HYPERVISOR, port))
                            .await
                        {
                            Ok(backend) => backend,
                            Err(error) => {
                                tracing::error!(?error, "failed to connect to backend");
                                return;
                            }
                        };
                    if let Err(error) = tokio::io::copy_bidirectional(&mut conn, &mut backend).await
                    {
                        tracing::error!(?error, "proxy copy failed");
                    }
                });
            }
        });
    }

    // control
    let mut listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, 1000))
        .with_context(|| "vsock bind failed: 1000")?;
    tokio::spawn(async move {
        loop {
            let (mut conn, peer_addr) = listener.accept().await.expect("control accept failed");
            let mut authorized_keys: Vec<u8> = Vec::new();
            if let Err(error) = conn.read_to_end(&mut authorized_keys).await {
                tracing::error!(?error, "failed to read authorized_keys on vsock port 1000");
                continue;
            }
            tracing::info!(?peer_addr, "received authorized_keys on vsock port 1000");
            if let Err(error) =
                tokio::fs::write("/home/user/.ssh/authorized_keys.new", authorized_keys).await
            {
                tracing::error!(?error, "failed to write authorized_keys.new");
                continue;
            }
            let _ = std::fs::set_permissions(
                "/home/user/.ssh/authorized_keys.new",
                std::fs::Permissions::from_mode(0o600),
            );
            let _ = std::os::unix::fs::chown(
                "/home/user/.ssh/authorized_keys.new",
                Some(1000),
                Some(1000),
            );
            let _ = tokio::fs::rename(
                "/home/user/.ssh/authorized_keys.new",
                "/home/user/.ssh/authorized_keys",
            )
            .await;
        }
    });

    let mut listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, 1))
        .with_context(|| "vsock bind failed: 1")?;

    loop {
        let (conn, peer_addr) = listener.accept().await?;

        tracing::info!(?peer_addr, "new connection");

        tokio::spawn(async move {
            match serve_once(nsm_fd, conn).await {
                Ok(()) => {}
                Err(error) => {
                    tracing::error!(?error, "error serving connection");
                }
            }
        });
    }
}

async fn serve_once(nsm_fd: i32, mut conn: VsockStream) -> anyhow::Result<()> {
    let mut their_public = [0u8; 32];
    conn.read_exact(&mut their_public).await?;
    let their_public = PublicKey::from(their_public);
    let our_secret = EphemeralSecret::random_from_rng(&mut rand::thread_rng());
    conn.write_all(PublicKey::from(&our_secret).as_bytes())
        .await?;
    let shared_secret = our_secret.diffie_hellman(&their_public);
    let attestation_cipher =
        ChaCha20Poly1305::new(&blake3::derive_key("attestation", shared_secret.as_bytes()).into());
    let proxy_req_cipher =
        ChaCha20Poly1305::new(&blake3::derive_key("proxy_req", shared_secret.as_bytes()).into());
    let c2s_cipher =
        ChaCha20Poly1305::new(&blake3::derive_key("c2s", shared_secret.as_bytes()).into());
    let s2c_cipher =
        ChaCha20Poly1305::new(&blake3::derive_key("s2c", shared_secret.as_bytes()).into());
    drop(shared_secret);

    let nsm_res = aws_nitro_enclaves_nsm_api::driver::nsm_process_request(
        nsm_fd,
        Request::Attestation {
            user_data: Some(Vec::from(&their_public.as_bytes()[..]).into()),
            nonce: None,
            public_key: None,
        },
    );
    let (conn_rx, conn_tx) = conn.into_split();
    let mut conn_rx = FramedRead::new(conn_rx, LengthDelimitedCodec::new());
    let mut conn_tx = FramedWrite::new(conn_tx, LengthDelimitedCodec::new());

    match nsm_res {
        Response::Attestation { document } => {
            let mut document = [&[1u8], &document[..]].concat();
            let tag = attestation_cipher
                .encrypt_in_place_detached(&[0u8; 12].into(), &[], &mut document)
                .map_err(|_| anyhow::anyhow!("attestation encryption failed"))?;
            let payload = [&document[..], &tag[..]].concat();
            conn_tx.send(Bytes::from(payload)).await?;
        }
        Response::Error(error) => {
            tracing::error!(?error, "error requesting nsm attestation");
        }
        _ => anyhow::bail!("unexpected nsm response"),
    }

    drop(attestation_cipher);

    let mut backend_addr = Vec::from(
        conn_rx
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("closed before backend address"))?
            .with_context(|| "failed to read backend address")?,
    );
    proxy_req_cipher
        .decrypt_in_place(&[0u8; 12].into(), &[], &mut backend_addr)
        .map_err(|_| anyhow::anyhow!("proxy_req decryption failed"))?;
    drop(proxy_req_cipher);
    if backend_addr.len() != 18 {
        anyhow::bail!("unexpected backend address size");
    }
    let backend_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&backend_addr[0..16]).unwrap());
    let backend_ip = match backend_ip.to_ipv4_mapped() {
        Some(ip) => ip,
        None => anyhow::bail!("backend address is not ipv4-mapped ipv6"),
    };
    let backend_port = u16::from_be_bytes(<[u8; 2]>::try_from(&backend_addr[16..18]).unwrap());
    let backend_addr = SocketAddr::new(backend_ip.into(), backend_port);
    let backend = TcpStream::connect(backend_addr)
        .await
        .with_context(|| "failed to connect to backend")?;
    let (backend_rx, backend_tx) = backend.into_split();

    tokio::select! {
        x = decrypt_and_copy(c2s_cipher, conn_rx, backend_tx) => x.with_context(|| "c2s failed"),
        x = encrypt_and_copy(s2c_cipher, backend_rx, conn_tx) => x.with_context(|| "s2c failed"),
    }
}

async fn decrypt_and_copy(
    cipher: ChaCha20Poly1305,
    mut from: impl Stream<Item = Result<BytesMut, std::io::Error>> + Unpin,
    mut to: impl AsyncWrite + Unpin,
) -> anyhow::Result<()> {
    let mut nonce: u64 = 1;

    loop {
        let Some(from) = from.next().await else {
            return Ok(());
        };
        let mut from = Vec::from(from.with_context(|| "read failed")?);

        let mut noncebuf = [0u8; 12];
        noncebuf[4..12].copy_from_slice(&nonce.to_be_bytes());
        nonce += 1;

        cipher
            .decrypt_in_place((&noncebuf).into(), &[], &mut from)
            .map_err(|_| anyhow::anyhow!("decrypt failed"))?;
        to.write_all(&from).await.with_context(|| "write failed")?;
    }
}

async fn encrypt_and_copy(
    cipher: ChaCha20Poly1305,
    mut from: impl AsyncRead + Unpin,
    mut to: impl Sink<Bytes, Error = std::io::Error> + Unpin,
) -> anyhow::Result<()> {
    let mut nonce: u64 = 1;
    let mut buf = vec![0u8; 1024 * 256];

    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        let buf = &mut buf[..n];

        let mut noncebuf = [0u8; 12];
        noncebuf[4..12].copy_from_slice(&nonce.to_be_bytes());
        nonce += 1;

        let tag = cipher
            .encrypt_in_place_detached(&noncebuf.into(), &[], buf)
            .map_err(|_| anyhow::anyhow!("encrypt failed"))?;
        let payload = [&buf[..], &tag[..]].concat();
        to.send(Bytes::from(payload))
            .await
            .with_context(|| "write failed")?;
    }
}
