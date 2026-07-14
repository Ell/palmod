#pragma once

#include <atomic>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <thread>
#include <sys/types.h>

namespace palmod {

class ControlServer {
 public:
  using Handler = std::function<std::string(std::string_view, uid_t)>;
  static constexpr std::size_t kMaxPacket = 64U * 1024U;

  ControlServer() = default;
  ~ControlServer();
  ControlServer(const ControlServer&) = delete;
  ControlServer& operator=(const ControlServer&) = delete;

  bool start(std::filesystem::path socket_path, Handler handler,
             std::string& error);
  void stop();
  const std::filesystem::path& path() const { return path_; }

 private:
  void run();
  void handle_client(int fd) const;
  std::filesystem::path path_;
  Handler handler_;
  std::atomic<bool> stopping_{false};
  int listen_fd_{-1};
  std::thread thread_;
};

}  // namespace palmod
