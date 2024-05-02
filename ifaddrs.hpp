// -*- C++ -*-
//
// Copyright 2024 Dmitry Igrishin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef DMITIGR_LIN_IFADDRS_HPP
#define DMITIGR_LIN_IFADDRS_HPP

#ifndef __linux__
#error dmitigr/lin/ifaddrs.hpp is usable only on Linux!
#endif

#include "../str/transform.hpp"

#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

// getifaddrs(3)
#include <sys/types.h>
#include <ifaddrs.h>

// packet(7)
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */

namespace dmitigr::lin {

/// A wrapper around ifaddrs.
class Ip_adapter_addresses final {
public:
  /// Constructs invalid instance.
  Ip_adapter_addresses()
    : data_{nullptr, &freeifaddrs}
  {}

  /// @warning May returns invalid instance.
  static Ip_adapter_addresses from_system()
  {
    Ip_adapter_addresses result;
    ifaddrs* data{};
    if (getifaddrs(&data))
      throw std::runtime_error{"cannot get network interface addresses"};
    result.data_.reset(data);
    return result;
  }

  /// @returns `true` is the instance is valid.
  bool is_valid() const noexcept
  {
    return static_cast<bool>(data_);
  }

  /// @returns `is_valid()`.
  explicit operator bool() const noexcept
  {
    return is_valid();
  }

  /// @returns The head of the linked list.
  const ifaddrs* head() const
  {
    if (!is_valid())
      throw std::logic_error{"cannot use invalid instance of type"
        " dmitigr::lin::Ip_adapter_addresses"};
    return reinterpret_cast<const ifaddrs*>(data_.get());
  }

  /// @overload
  ifaddrs* head()
  {
    return const_cast<ifaddrs*>(
      static_cast<const Ip_adapter_addresses*>(this)->head());
  }

private:
  std::unique_ptr<ifaddrs, void(*)(ifaddrs*)> data_;
};

/**
 * @returns A textual representation of a physical address of `iaa`.
 *
 * @par Requires
 * `iaa.ifa_addr && iaa.ifa_addr->sa_family == AF_PACKET`.
 */
inline std::string physical_address_string(const ifaddrs& iaa,
  const std::string_view delimiter = "-")
{
  if (!iaa.ifa_addr || iaa.ifa_addr->sa_family != AF_PACKET)
    throw std::invalid_argument{"cannot get physical address from not AF_PACKET family"};

  const auto* const sll = reinterpret_cast<const sockaddr_ll*>(iaa.ifa_addr);

  return dmitigr::str::sparsed_string(std::string_view{
      reinterpret_cast<const char*>(sll->sll_addr), sll->sll_halen},
    dmitigr::str::Byte_format::hex, delimiter);
}

} // namespace dmitigr::lin

#endif  // DMITIGR_LIN_IFADDRS_HPP
