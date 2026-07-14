#include "palmod/control_server.hpp"

#include "palmod/json.hpp"
#include "palmod/json_log.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace palmod {
namespace {

std::string error_packet(std::string_view message) {
  return "{\"id\":null,\"ok\":false,\"error\":{\"code\":\"protocol_error\",\"message\":\"" +
         json::escape(message) + "\"}}";
}

bool safe_remove_stale(const std::filesystem::path& path, std::string& error) {
  struct stat status{};
  if (lstat(path.c_str(), &status) != 0) {
    if (errno == ENOENT) return true;
    error = "cannot inspect control socket path: " + std::string(std::strerror(errno));
    return false;
  }
  if (!S_ISSOCK(status.st_mode) || status.st_uid != geteuid()) {
    error = "refusing to replace a non-socket or foreign-owned control path";
    return false;
  }
  if (unlink(path.c_str()) != 0) {
    error = "cannot remove stale control socket: " + std::string(std::strerror(errno));
    return false;
  }
  return true;
}

}  // namespace

ControlServer::~ControlServer() { stop(); }

bool ControlServer::start(std::filesystem::path socket_path, Handler handler,
                          std::string& error) {
  if (thread_.joinable()) {
    error = "control server is already running";
    return false;
  }
  if (!socket_path.is_absolute()) {
    error = "control socket path must be absolute";
    return false;
  }
  const std::string encoded = socket_path.string();
  if (encoded.size() >= sizeof(sockaddr_un::sun_path)) {
    error = "control socket path is too long for AF_UNIX";
    return false;
  }
  if (!safe_remove_stale(socket_path, error)) return false;

  const int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    error = "socket(AF_UNIX) failed: " + std::string(std::strerror(errno));
    return false;
  }
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  std::memcpy(address.sun_path, encoded.c_str(), encoded.size() + 1);
  if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    error = "bind(control socket) failed: " + std::string(std::strerror(errno));
    close(fd);
    return false;
  }
  if (chmod(encoded.c_str(), S_IRUSR | S_IWUSR) != 0) {
    error = "chmod(control socket) failed: " + std::string(std::strerror(errno));
    close(fd);
    unlink(encoded.c_str());
    return false;
  }
  if (listen(fd, 8) != 0) {
    error = "listen(control socket) failed: " + std::string(std::strerror(errno));
    close(fd);
    unlink(encoded.c_str());
    return false;
  }
  path_ = std::move(socket_path);
  handler_ = std::move(handler);
  stopping_.store(false);
  listen_fd_ = fd;
  thread_ = std::thread([this] { run(); });
  return true;
}

void ControlServer::stop() {
  if (!thread_.joinable()) return;
  stopping_.store(true);
  shutdown(listen_fd_, SHUT_RDWR);
  thread_.join();
  close(listen_fd_);
  listen_fd_ = -1;
  if (!path_.empty()) unlink(path_.c_str());
  path_.clear();
  handler_ = {};
}

void ControlServer::run() {
  while (!stopping_.load()) {
    const int client = accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
    if (client < 0) {
      if (stopping_.load()) break;
      if (errno == EINTR) continue;
      JsonLog::instance().write(JsonLog::Level::Warn, "control.accept_failed",
                                std::strerror(errno));
      continue;
    }
    handle_client(client);
    close(client);
  }
}

void ControlServer::handle_client(int fd) const {
  ucred credentials{};
  socklen_t credentials_size = sizeof(credentials);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &credentials_size) != 0 ||
      credentials.uid != geteuid()) {
    const auto response = error_packet("peer credentials rejected");
    send(fd, response.data(), response.size(), MSG_NOSIGNAL);
    return;
  }
  timeval timeout{2, 0};
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  std::array<char, kMaxPacket> buffer{};
  iovec vector{buffer.data(), buffer.size()};
  msghdr message{};
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  const ssize_t received = recvmsg(fd, &message, MSG_TRUNC);
  std::string response;
  if (received <= 0) {
    response = error_packet("expected one non-empty JSON packet");
  } else if ((message.msg_flags & MSG_TRUNC) != 0 ||
             static_cast<std::size_t>(received) > buffer.size()) {
    response = error_packet("request exceeds 64 KiB");
  } else if (handler_) {
    response = handler_(std::string_view(buffer.data(), static_cast<std::size_t>(received)),
                        credentials.uid);
  } else {
    response = error_packet("control handler unavailable");
  }
  if (response.size() > kMaxPacket) response = error_packet("response exceeds 64 KiB");
  send(fd, response.data(), response.size(), MSG_NOSIGNAL);
}

}  // namespace palmod
