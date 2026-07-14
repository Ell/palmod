use std::fs;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{
    AddressFamily, MsgFlags, SockFlag, SockType, UnixAddr, connect, getsockopt, recv, send, socket,
    sockopt,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_PACKET_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRequest {
    pub id: u64,
    pub method: String,
    pub params: serde_json::Map<String, Value>,
}

impl ControlRequest {
    #[must_use]
    pub fn status(id: u64) -> Self {
        Self {
            id,
            method: "status".to_owned(),
            params: serde_json::Map::new(),
        }
    }

    #[must_use]
    pub fn reload(id: u64, plugin: Option<String>) -> Self {
        let mut params = serde_json::Map::new();
        if let Some(plugin) = plugin {
            params.insert("plugin".to_owned(), Value::String(plugin));
        }
        Self {
            id,
            method: "plugins.reload".to_owned(),
            params,
        }
    }

    #[must_use]
    pub fn invoke(id: u64, command: String, args: Vec<String>) -> Self {
        let params = serde_json::Map::from_iter([
            ("command".to_owned(), Value::String(command)),
            (
                "args".to_owned(),
                Value::Array(args.into_iter().map(Value::String).collect()),
            ),
        ]);
        Self {
            id,
            method: "command.invoke".to_owned(),
            params,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlResponse {
    pub id: u64,
    pub ok: bool,
    pub result: Option<Value>,
    pub error: Option<ControlError>,
}

impl ControlResponse {
    pub fn validate_for(&self, request_id: u64) -> Result<()> {
        ensure!(
            self.id == request_id,
            "response ID {} does not match request ID {request_id}",
            self.id
        );
        match (self.ok, &self.error) {
            (true, None) | (false, Some(_)) => Ok(()),
            (true, Some(_)) => bail!("successful response unexpectedly contains an error"),
            (false, None) => bail!("failed response is missing its error object"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlError {
    pub code: String,
    pub message: String,
}

pub struct ControlClient {
    socket: OwnedFd,
    timeout: Duration,
    path: PathBuf,
}

impl ControlClient {
    pub fn connect(path: impl AsRef<Path>, timeout: Duration) -> Result<Self> {
        let path = path.as_ref();
        ensure!(path.is_absolute(), "control socket path must be absolute");
        let metadata = fs::metadata(path)
            .with_context(|| format!("reading control socket metadata {}", path.display()))?;
        ensure!(
            metadata.file_type().is_socket(),
            "not a Unix socket: {}",
            path.display()
        );
        let canonical = path
            .canonicalize()
            .with_context(|| format!("resolving {}", path.display()))?;
        let address = UnixAddr::new(&canonical)
            .with_context(|| format!("invalid Unix socket path {}", canonical.display()))?;
        let socket = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None,
        )?;
        connect(socket.as_raw_fd(), &address)
            .with_context(|| format!("connecting to {}", canonical.display()))?;

        // Filesystem ownership and SO_PEERCRED must describe the same local service.
        let peer = getsockopt(&socket, sockopt::PeerCredentials)?;
        ensure!(
            peer.uid() == metadata.uid(),
            "socket owner uid {} differs from peer uid {}",
            metadata.uid(),
            peer.uid()
        );
        Ok(Self {
            socket,
            timeout,
            path: canonical,
        })
    }

    pub fn call(&self, request: &ControlRequest) -> Result<ControlResponse> {
        ensure!(
            matches!(
                request.method.as_str(),
                "status" | "plugins.reload" | "command.invoke"
            ),
            "unsupported control method {}",
            request.method
        );
        let encoded = serde_json::to_vec(request)?;
        ensure!(
            encoded.len() <= MAX_PACKET_SIZE,
            "request is {} bytes; packet limit is {MAX_PACKET_SIZE}",
            encoded.len()
        );
        let sent = send(self.socket.as_raw_fd(), &encoded, MsgFlags::MSG_NOSIGNAL)
            .with_context(|| format!("sending request to {}", self.path.display()))?;
        ensure!(
            sent == encoded.len(),
            "partial SOCK_SEQPACKET send ({sent}/{})",
            encoded.len()
        );

        let timeout_ms = u64::try_from(self.timeout.as_millis()).unwrap_or(u64::MAX);
        let timeout = PollTimeout::try_from(timeout_ms).unwrap_or(PollTimeout::MAX);
        let mut poll_fd = [PollFd::new(self.socket.as_fd(), PollFlags::POLLIN)];
        let ready = poll(&mut poll_fd, timeout)?;
        ensure!(ready > 0, "timed out waiting for palmod control response");
        let events = poll_fd[0].revents().unwrap_or_else(PollFlags::empty);
        ensure!(
            !events.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL),
            "control socket failed: {events:?}"
        );

        // One extra byte lets us reject an oversized packet rather than accepting
        // a valid-looking truncated JSON prefix.
        let mut packet = vec![0_u8; MAX_PACKET_SIZE + 1];
        let received = recv(self.socket.as_raw_fd(), &mut packet, MsgFlags::empty())
            .with_context(|| format!("receiving response from {}", self.path.display()))?;
        ensure!(received > 0, "control socket closed without a response");
        ensure!(
            received <= MAX_PACKET_SIZE,
            "response exceeds {MAX_PACKET_SIZE}-byte packet limit"
        );
        packet.truncate(received);
        let response: ControlResponse =
            serde_json::from_slice(&packet).context("decoding control response JSON packet")?;
        response.validate_for(request.id)?;
        Ok(response)
    }
}

/// Derive the same user-private default used by `palmod-run`.
pub fn default_socket_path() -> Result<PathBuf> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
        || PathBuf::from(format!("/run/user/{}", nix::unistd::getuid().as_raw())),
        PathBuf::from,
    );
    ensure!(
        runtime_dir.is_absolute(),
        "XDG_RUNTIME_DIR must be absolute"
    );
    Ok(runtime_dir.join("palmod/control.sock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_shape_is_the_wire_contract() {
        let request = ControlRequest::invoke(
            42,
            "GiveItem".to_owned(),
            vec!["PalSphere".to_owned(), "Alice".to_owned()],
        );
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({
                "id": 42,
                "method": "command.invoke",
                "params": {"command": "GiveItem", "args": ["PalSphere", "Alice"]}
            })
        );
    }

    #[test]
    fn inconsistent_response_is_rejected() {
        let response = ControlResponse {
            id: 4,
            ok: true,
            result: None,
            error: Some(ControlError {
                code: "bad".to_owned(),
                message: "bad".to_owned(),
            }),
        };
        assert!(response.validate_for(4).is_err());
        assert!(response.validate_for(3).is_err());
    }

    #[test]
    fn oversized_request_is_detectable_before_io() {
        let request = ControlRequest::invoke(1, "x".repeat(MAX_PACKET_SIZE), Vec::new());
        assert!(serde_json::to_vec(&request).unwrap().len() > MAX_PACKET_SIZE);
    }

    #[test]
    fn seqpacket_round_trip_preserves_one_json_object_per_packet() {
        use nix::sys::socket::{Backlog, accept, bind, listen};
        use nix::unistd::close;

        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("control.sock");
        let listener = socket(
            AddressFamily::Unix,
            SockType::SeqPacket,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .unwrap();
        bind(listener.as_raw_fd(), &UnixAddr::new(&path).unwrap()).unwrap();
        listen(&listener, Backlog::new(1).unwrap()).unwrap();

        let server = std::thread::spawn(move || {
            let accepted = accept(listener.as_raw_fd()).unwrap();
            let mut packet = vec![0_u8; MAX_PACKET_SIZE];
            let length = recv(accepted, &mut packet, MsgFlags::empty()).unwrap();
            packet.truncate(length);
            let request: serde_json::Value = serde_json::from_slice(&packet).unwrap();
            assert_eq!(request["method"], "status");
            let response = serde_json::json!({
                "id": request["id"],
                "ok": true,
                "result": {"profile": "test"},
                "error": null
            });
            let encoded = serde_json::to_vec(&response).unwrap();
            assert_eq!(
                send(accepted, &encoded, MsgFlags::MSG_NOSIGNAL).unwrap(),
                encoded.len()
            );
            close(accepted).unwrap();
        });

        let client = ControlClient::connect(&path, Duration::from_secs(1)).unwrap();
        let response = client.call(&ControlRequest::status(77)).unwrap();
        assert_eq!(response.result.unwrap()["profile"], "test");
        server.join().unwrap();
    }
}
