use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::error::{DavError, Result};
use super::http::{not_implemented_response, parse_request_head, split_head_from_buffer};

pub struct DavServer {
    listener: TcpListener,
}

impl DavServer {
    pub fn from_listener(listener: TcpListener) -> Self {
        Self { listener }
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub fn spawn(self) -> DavServerHandle {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let join = tokio::spawn(self.run(shutdown_rx));
        DavServerHandle {
            shutdown_tx: Some(shutdown_tx),
            join,
        }
    }

    pub async fn run(self, mut shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                accepted = self.listener.accept() => {
                    let (stream, _addr) = accepted?;
                    spawn_placeholder_handler(stream);
                }
            }
        }

        Ok(())
    }
}

pub struct DavServerHandle {
    shutdown_tx: Option<oneshot::Sender<()>>,
    join: JoinHandle<Result<()>>,
}

impl DavServerHandle {
    pub async fn stop(mut self) -> Result<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        self.wait().await
    }

    pub async fn wait(self) -> Result<()> {
        match self.join.await {
            Ok(result) => result,
            Err(err) => Err(DavError::Io(std::io::Error::other(format!(
                "dav task join error: {err}"
            )))),
        }
    }
}

pub async fn run_server(addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    run_server_with_listener(listener).await
}

pub async fn run_server_with_listener(listener: TcpListener) -> Result<()> {
    let listener_addr = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    tracing::info!(addr = %listener_addr, "DAV placeholder server listening");

    loop {
        let (stream, _addr) = listener.accept().await?;
        spawn_placeholder_handler(stream);
    }
}

fn spawn_placeholder_handler(stream: TcpStream) {
    tokio::spawn(async move {
        if let Err(err) = handle_connection(stream).await {
            tracing::warn!(error = %err, "dav placeholder request failed");
        }
    });
}

pub async fn handle_connection(mut stream: TcpStream) -> Result<()> {
    let mut buffer = vec![0_u8; 4096];
    let mut received = Vec::with_capacity(4096);

    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            return Err(DavError::InvalidRequest(
                "client disconnected before request",
            ));
        }

        received.extend_from_slice(&buffer[..n]);
        match split_head_from_buffer(&received) {
            Ok(head_end) => {
                let _request = parse_request_head(&received[..head_end])?;
                let wire = not_implemented_response().to_bytes();
                stream.write_all(&wire).await?;
                stream.flush().await?;
                return Ok(());
            }
            Err(DavError::InvalidRequest("incomplete headers")) => continue,
            Err(err) => {
                let status = err.status_line();
                let wire =
                    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                stream.write_all(wire.as_bytes()).await?;
                stream.flush().await?;
                return Err(err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{DavServer, Result};

    #[tokio::test]
    async fn placeholder_server_replies_with_501() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let server = DavServer::from_listener(listener);
        let addr = server.local_addr()?;
        let handle = server.spawn();

        let mut client = tokio::net::TcpStream::connect(addr).await?;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await?;

        let mut response = vec![0_u8; 512];
        let n = client.read(&mut response).await?;
        let wire = String::from_utf8_lossy(&response[..n]);

        assert!(wire.starts_with("HTTP/1.1 501 Not Implemented\r\n"));
        assert!(wire.contains("DAV: 1, 2, calendar-access, addressbook\r\n"));

        handle.stop().await?;
        Ok(())
    }
}
