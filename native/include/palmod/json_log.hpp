#pragma once

#include <initializer_list>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

namespace palmod {

class JsonLog {
 public:
  enum class Level { Debug, Info, Warn, Error };
  using Field = std::pair<std::string_view, std::string_view>;

  static JsonLog& instance();
  void write(Level level, std::string_view event, std::string_view message,
             std::initializer_list<Field> fields = {});

 private:
  std::mutex mu_;
};

}  // namespace palmod
