#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace palmod {

// Convert host-endian UTF-16 code units (Unreal's TCHAR on this build) to UTF-8.
// Unpaired or invalid surrogates become U+FFFD; a null pointer yields "". The
// count bounds the read so a corrupt FString length cannot run away.
std::string utf16_to_utf8(const char16_t* units, std::size_t count);

// Convert UTF-8 to host-endian UTF-16 (Unreal's TCHAR). Invalid/overlong byte
// sequences become U+FFFD. The result is not null-terminated; callers building
// an FString append the terminator and set Num = size()+1.
std::u16string utf8_to_utf16(std::string_view utf8);

}  // namespace palmod
