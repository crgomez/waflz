//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_nms.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    12/06/2016
//:
//:   Licensed under the Apache License, Version 2.0 (the "License");
//:   you may not use this file except in compliance with the License.
//:   You may obtain a copy of the License at
//:
//:       http://www.apache.org/licenses/LICENSE-2.0
//:
//:   Unless required by applicable law or agreed to in writing, software
//:   distributed under the License is distributed on an "AS IS" BASIS,
//:   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//:   See the License for the specific language governing permissions and
//:   limitations under the License.
//:
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/def.h"
#include "op/nms.h"
//: ----------------------------------------------------------------------------
//: read_file
//: ----------------------------------------------------------------------------
TEST_CASE( "nms basic test", "[nms_basic]" ) {
        SECTION("ipv4 basic insert") {
                int32_t l_s;
                ns_waflz::nms *l_nms = new ns_waflz::nms();
                l_s = l_nms->add("127.0.0.1", sizeof("127.0.0.1"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_nms->add("192.168.100.0/24", sizeof("192.168.100.0/24"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                bool l_m;
                l_s = l_nms->contains(l_m, "127.0.0.1", sizeof("127.0.0.1"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                l_s = l_nms->contains(l_m, "192.168.100.1", sizeof("192.168.100.1"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                l_s = l_nms->contains(l_m, "192.168.100.12", sizeof("192.168.100.12"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                // captures buffer overflow
                l_s = l_nms->contains(l_m, "192.168.100.0", sizeof("192.168.100.0"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                l_s = l_nms->contains(l_m, "193.164.100.12", sizeof("193.164.100.12"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == false));
                if(l_nms) { delete l_nms; l_nms = NULL;}
        }
        SECTION("ipv6 basic insert") {
                int32_t l_s;
                ns_waflz::nms *l_nms = new ns_waflz::nms();
                l_s = l_nms->add("2001:0db8:85a3:0000:0000:8a2e:0370:7334", sizeof("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_nms->add("2222:0db8:85a3:0001:0001:8a2e:0370::/112", sizeof("2222:0db8:85a3:0001:0001:8a2e:0370::/112"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                void *l_node;
                bool l_m;
                l_s = l_nms->contains(l_m, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", sizeof("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                l_s = l_nms->contains(l_m, "2001:0db8:85a3:0000:0000:8a2f:0370:7334", sizeof("2001:0db8:85a3:0000:0000:8a2f:0370:7334"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == false));
                l_s = l_nms->contains(l_m, "2222:0db8:85a3:0001:0001:8a2e:0370:0001", sizeof("2222:0db8:85a3:0001:0001:8a2e:0370:0001"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                l_s = l_nms->contains(l_m, "2222:0db8:85a3:0001:0001:8a2e:0370:0000", sizeof("2222:0db8:85a3:0001:0001:8a2e:0370:0000"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == true));
                l_s = l_nms->contains(l_m, "2222:0db8:85a3:0001:0001:8a2e:0371:0001", sizeof("2222:0db8:85a3:0001:0001:8a2e:0371:0001"));
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                REQUIRE((l_m == false));
                if(l_nms) { delete l_nms; l_nms = NULL;}
        }
}
