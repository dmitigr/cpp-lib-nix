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

#include "../../base/assert.hpp"
#include "../lin.hpp"

int main()
{
  try {
    namespace lin = dmitigr::lin;

    using std::cout;
    using std::endl;

    if (const auto iaas = lin::Ip_adapter_addresses::from_system()) {
      for (auto* iaa = iaas.head(); iaa; iaa = iaa->ifa_next) {
        const auto family = iaa->ifa_addr->sa_family;
        if (family == AF_PACKET) {
          cout << "Adapter " << iaa->ifa_name << ":" << endl;
          const auto mac = lin::physical_address_string(*iaa);
          cout << "  physical address: " << (mac.empty() ? "null" : mac) << endl;
        }
      }
    } else
      cout << "no network adapters found";
  } catch (const std::exception& e) {
    std::cerr << e.what() << std::endl;
    return 1;
  } catch (...) {
    std::cerr << "unknown error" << std::endl;
    return 2;
  }
}
