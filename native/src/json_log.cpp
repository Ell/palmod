#include "palmod/json_log.hpp"

#include "palmod/json.hpp"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <unistd.h>

namespace palmod {

JsonLog& JsonLog::instance() {
  static JsonLog logger;
  return logger;
}

void JsonLog::write(Level level, std::string_view event, std::string_view message,
                    std::initializer_list<Field> fields) {
  const char* level_name = "info";
  switch (level) {
    case Level::Debug: level_name = "debug"; break;
    case Level::Info: level_name = "info"; break;
    case Level::Warn: level_name = "warn"; break;
    case Level::Error: level_name = "error"; break;
  }

  const auto now = std::chrono::system_clock::now();
  const auto seconds = std::chrono::system_clock::to_time_t(now);
  std::tm utc{};
  gmtime_r(&seconds, &utc);
  char timestamp[32]{};
  std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc);

  std::string line = "{\"ts\":\"";
  line += timestamp;
  line += "\",\"level\":\"";
  line += level_name;
  line += "\",\"component\":\"palmod\",\"event\":\"";
  line += json::escape(event);
  line += "\",\"message\":\"";
  line += json::escape(message);
  line += "\",\"pid\":";
  line += std::to_string(getpid());
  for (const auto& [key, value] : fields) {
    line += ",\"";
    line += json::escape(key);
    line += "\":\"";
    line += json::escape(value);
    line += '"';
  }
  line += "}\n";

  std::scoped_lock lock(mu_);
  std::fwrite(line.data(), 1, line.size(), stderr);
  std::fflush(stderr);
}

}  // namespace palmod
