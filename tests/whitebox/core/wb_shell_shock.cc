//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_shell_shock.cc
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
//: includes
//: ----------------------------------------------------------------------------
#include "catch/catch.hpp"
#include "waflz/engine.h"
#include "waflz/def.h"
#include "waflz/profile.h"
#include "waflz/waf.h"
#include "proto/rule.pb.h"
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define MSX_SHELL_SHOCK_RULE "SecRule REQUEST_HEADERS|REQUEST_LINE|REQUEST_BODY|REQUEST_HEADERS_NAMES \"@contains () {\" \"phase:2,rev:'1',ver:'EC/1.0.0',maturity:'1',accuracy:'8',t:none,t:urlDecodeUni,t:Utf8toUnicode,id:'431000',msg:'Bash shellshock attack detected',tag:'CVE-2014-6271',block\""
//: ----------------------------------------------------------------------------
//: read_file
//: ----------------------------------------------------------------------------
TEST_CASE( "shell shock", "[shell_shock]" ) {

        // -------------------------------------------------
        // TODO FIX!!!!!!!
        // -------------------------------------------------
#if 0
        SECTION("basic parse test") {
                ns_waflz::engine *l_engine = new ns_waflz::engine();
                ns_waflz::waf *l_wafl = new ns_waflz::waf(*l_engine);
                std::string l_str = MSX_SHELL_SHOCK_RULE;
                int32_t l_s;
                l_s = l_wafl->init_line(ns_waflz::config_parser::MODSECURITY, l_str);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                const waflz_pb::sec_config_t *l_pb = NULL;
                l_pb = l_wafl->get_config();
                //printf("directive size: %d\n", (int)l_pb->directive_size());
                REQUIRE((l_pb != NULL));
                //REQUIRE((l_pb->directive_size() == 1));
                waflz_pb::directive_t l_directive = l_pb->directive(0);
                const ::waflz_pb::sec_rule_t& l_r = l_directive.sec_rule();
                REQUIRE((l_r.has_action() == true));
                const ::waflz_pb::sec_action_t& l_a = l_r.action();
                REQUIRE((l_a.has_id() == true));
                REQUIRE((l_a.id() == "431000"));
                REQUIRE((l_a.tag_size() == 1));
                REQUIRE((l_a.tag(0) == "CVE-2014-6271"));
                REQUIRE((l_a.msg() == "Bash shellshock attack detected"));
                if(l_wafl) { delete l_wafl; l_wafl = NULL; }
                if(l_engine) { delete l_engine; l_engine = NULL; }
        }
#endif
}
