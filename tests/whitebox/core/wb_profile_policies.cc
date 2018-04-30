//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wb_profile_policies.cc
//: \details: TODO
//: \author:  Devender Singh
//: \date:    02/09/2018
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
#include "waflz/engine.h"
#include "waflz/profile.h"
#include "waflz/instances.h"
#include "config.pb.h"
#include "support/ndebug.h"
#include "support/geoip2_mmdb.h"
#include <unistd.h>
//: ----------------------------------------------------------------------------
//: TODO
//: ----------------------------------------------------------------------------
static waflz_pb::profile *init_std_profile_pb(void)
{
        // -----------------------------------------
        // setup...
        // -----------------------------------------
        waflz_pb::profile *l_pb = NULL;
        l_pb = new waflz_pb::profile();
        l_pb->set_id("my_id");
        l_pb->set_name("my_name");
        l_pb->set_ruleset_id("MONKEYRULE");
        l_pb->set_ruleset_version("2018-02-12");
        // -----------------------------------------
        // general settings -required fields
        // -----------------------------------------
        ::waflz_pb::profile_general_settings_t* l_gx = NULL;
        l_gx = l_pb->mutable_general_settings();
        l_gx->set_process_request_body(true);
        l_gx->set_xml_parser(true);
        l_gx->set_process_response_body(false);
        l_gx->set_engine("anomaly");
        l_gx->set_validate_utf8_encoding(true);
        l_gx->set_max_num_args(3);
        l_gx->set_arg_name_length(100);
        l_gx->set_arg_length(400);
        l_gx->set_total_arg_length(64000);
        l_gx->set_max_file_size(1048576);
        l_gx->set_combined_file_sizes(1048576);
        l_gx->add_allowed_http_methods("GET");
        l_gx->add_allowed_request_content_types("html");
        // -----------------------------------------
        // anomaly settings -required fields
        // -----------------------------------------
        ::waflz_pb::profile_general_settings_t_anomaly_settings_t* l_gx_anomaly = NULL;
        l_gx_anomaly = l_gx->mutable_anomaly_settings();
        l_gx_anomaly->set_critical_score(5);
        l_gx_anomaly->set_error_score(4);
        l_gx_anomaly->set_warning_score(3);
        l_gx_anomaly->set_notice_score(2);
        l_gx_anomaly->set_inbound_threshold(1);
        l_gx_anomaly->set_outbound_threshold(4);
        // -----------------------------------------
        // access settings -required fields
        // -----------------------------------------
        ::waflz_pb::profile_access_settings_t* l_ax = NULL;
        l_ax = l_pb->mutable_access_settings();
        ::waflz_pb::profile_access_settings_t_lists_t* l_ax_ip = l_ax->mutable_ip();
        UNUSED(l_ax_ip);
        ::waflz_pb::profile_access_settings_t_lists_t* l_ax_cntry = l_ax->mutable_country();
        UNUSED(l_ax_cntry);
        ::waflz_pb::profile_access_settings_t_lists_t* l_ax_url = l_ax->mutable_url();
        UNUSED(l_ax_url);
        ::waflz_pb::profile_access_settings_t_lists_t* l_ax_refr = l_ax->mutable_referer();
        UNUSED(l_ax_refr);
        return l_pb;
}

//: ----------------------------------------------------------------------------
//: profile acl tests
//: ----------------------------------------------------------------------------
TEST_CASE( "profile policies test", "[profile_policies]" )
{
        // -----------------------------------------
        // get ruleset dir
        // -----------------------------------------
        char l_cwd[1024];
        if(getcwd(l_cwd, sizeof(l_cwd)) != NULL)
        {
            //fprintf(stdout, "Current working dir: %s\n", cwd);
        }
        std::string l_rule_dir = l_cwd;
        l_rule_dir += "/../../../../tests/data/waf/ruleset/";
        //l_rule_dir += "/../tests/data/waf/ruleset/";
        ns_waflz::profile::s_ruleset_dir = l_rule_dir;
        // -----------------------------------------
        // geoip
        // -----------------------------------------
        std::string l_geoip2_city_file = l_cwd;
        std::string l_geoip2_asn_file = l_cwd;
        l_geoip2_city_file += "/../../../../tests/data/waf/db/GeoLite2-City.mmdb";
        //l_geoip2_city_file += "/../tests/data/waf/db/GeoLite2-City.mmdb";
        l_geoip2_asn_file += "/../../../../tests/data/waf/db/GeoLite2-ASN.mmdb";
        //l_geoip2_asn_file += "/../tests/data/waf/db/GeoLite2-ASN.mmdb";
        ns_waflz::profile::s_geoip2_db = l_geoip2_city_file;
        ns_waflz::profile::s_geoip2_isp_db = l_geoip2_asn_file;
        // -------------------------------------------------
        // acl
        // -------------------------------------------------
        SECTION("policy test, no disable_policy") {
                // -----------------------------------------
                // setup
                // -----------------------------------------
                ns_waflz::geoip2_mmdb *l_geoip2_mmdb = new ns_waflz::geoip2_mmdb();
                int32_t l_s;
                l_s = l_geoip2_mmdb->init(ns_waflz::profile::s_geoip2_db,
                                          ns_waflz::profile::s_geoip2_isp_db);
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::engine *l_engine = new ns_waflz::engine();
                l_s = l_engine->init();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                l_s = l_engine->init_post_fork();
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                ns_waflz::profile *l_profile = new ns_waflz::profile(*l_engine, *l_geoip2_mmdb);
                waflz_pb::profile *l_pb = init_std_profile_pb();
                //-------------------------------------------
                // Load config with default policies
                //-------------------------------------------
                l_s = l_profile->load_config(l_pb, false);
                //NDBG_PRINT("error[%d]: %s\n", l_s, l_profile->get_err_msg());
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                //---------------------------------------------
                // Disable the policy with anomaly enfore rule
                //---------------------------------------------
                ::waflz_pb::profile_disabled_policy_t *l_disabled_policy = l_pb->add_disabled_policies();
                l_disabled_policy->set_policy_id("REQUEST-949-BLOCKING-EVALUATION.conf");
                //fprintf(stdout, "%s\n", l_pb->DebugString().c_str());

                l_s = l_profile->load_config(l_pb, false);
                //---------------------------------------------
                // Should fail to load config
                //---------------------------------------------
                REQUIRE((l_s == WAFLZ_STATUS_ERROR));
                //---------------------------------------------
                // Now include the anomaly rule file
                // This would ignore the disabled policies
                // and config should load
                //---------------------------------------------
                ::waflz_pb::profile_policy_t *l_policy = l_pb->add_policies();
                l_policy->set_policy_id("REQUEST-949-BLOCKING-EVALUATION.conf");
                l_s = l_profile->load_config(l_pb, false);
                //---------------------------------------------
                // Should fail to load config
                //---------------------------------------------
                REQUIRE((l_s == WAFLZ_STATUS_OK));
                // -----------------------------------------
                // finalize
                // -----------------------------------------
                l_engine->finalize();
                // -----------------------------------------
                // cleanup
                // -----------------------------------------
                l_engine->shutdown();
                if(l_profile)
                {
                        delete l_profile;
                        l_profile = NULL;
                }
                if(l_pb)
                {
                        delete l_pb;
                        l_pb = NULL;
                }
                if(l_engine)
                {
                        delete l_engine;
                        l_engine = NULL;
                }
                if(l_geoip2_mmdb)
                {
                        delete l_geoip2_mmdb;
                        l_geoip2_mmdb = NULL;
                }
        }
}
