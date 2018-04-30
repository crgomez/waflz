//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    waf.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    09/30/2015
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
// ---------------------------------------------------------
// proto
// ---------------------------------------------------------
#include "rule.pb.h"
#include "event.pb.h"
#include "config.pb.h"
// ---------------------------------------------------------
// internal
// ---------------------------------------------------------
#include "waflz/def.h"
#include "waflz/waf.h"
#include "waflz/rqst_ctx.h"
#include "waflz/engine.h"
#include "waflz/profile.h"
#include "op/regex.h"
#include "op/ac.h"
#include "support/ndebug.h"
#include "support/file_util.h"
#include "support/md5_hasher.h"
#include "core/op.h"
#include "core/var.h"
#include "core/tx.h"
#include "core/macro.h"
#include "jspb/jspb.h"
#include <unistd.h>
#include <dirent.h>
//: ----------------------------------------------------------------------------
//: constants
//: ----------------------------------------------------------------------------
#define WAFLZ_NATIVE_ANOMALY_MODE 1
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#define DEL_LAST_CHAR(_str) _str.erase(_str.size() - 1)
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
waf::waf(engine &a_engine):
        _waf(a_engine),
        // -------------------------------------------------
        // protobuf
        // -------------------------------------------------
        m_pb(NULL),
        // -------------------------------------------------
        // compiled
        // -------------------------------------------------
        m_compiled_config(NULL),
        m_ctype_parser_map(a_engine.get_ctype_parser_map()),
        m_disabled_rule_id_set()
{
        m_compiled_config = new compiled_config_t();
        m_pb = new waflz_pb::sec_config_t();
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
waf::~waf()
{
        if(m_compiled_config) { delete m_compiled_config; m_compiled_config = NULL; }
        if(m_pb) { delete m_pb; m_pb = NULL; }
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
#if 0
void waf::show(void)
{
        std::string l_config = m_pb->DebugString();
        colorize_string(l_config);
        NDBG_OUTPUT("%s\n", l_config.c_str());
}
#endif
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
#if 0
void waf::show_status(void)
{
        m_parser.show_status();
}
#endif
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::get_str(std::string &ao_str, config_parser::format_t a_format)
{
        bool l_s;
        switch(a_format)
        {
        // ---------------------------------------
        // Protobuf
        // ---------------------------------------
        case config_parser::PROTOBUF:
        {
                l_s = m_pb->SerializeToString(&ao_str);
                if(!l_s)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                else
                {
                        return WAFLZ_STATUS_OK;
                }
                break;
        }
        // ---------------------------------------
        // json
        // ---------------------------------------
        case config_parser::JSON:
        {
                // convert protobuf message to JsonCpp object
                try
                {
                        ns_jspb::convert_to_json(ao_str, *m_pb);
                }
                catch(int e)
                {
                        NDBG_PRINT("Error -json_protobuf::convert_to_json threw\n");
                        return WAFLZ_STATUS_ERROR;
                }
                return WAFLZ_STATUS_OK;
        }
        // ---------------------------------------
        // modsecurity
        // ---------------------------------------
        case config_parser::MODSECURITY:
        {
                l_s = config_parser::get_modsec_config_str(ao_str, *m_pb);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        //NDBG_PRINT("Error performing get_modsec_config_str\n");
                        return WAFLZ_STATUS_ERROR;
                }
                else
                {
                        return WAFLZ_STATUS_OK;
                }
                break;
        }
        default:
        {
                NDBG_PRINT("Error -unrecognized format specification[%d]\n", a_format);
                return WAFLZ_STATUS_ERROR;
        }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::init(config_parser::format_t a_format, const std::string &a_path)
{
        // Check if already is initd
        if(m_is_initd)
        {
                return WAFLZ_STATUS_OK;
        }
        int32_t l_s;
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        config_parser *l_parser = new config_parser();
        l_s = l_parser->parse_config(*m_pb, a_format, a_path);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_parser) { delete l_parser; l_parser = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // TODO remove -debug...
        //l_parser->show_status();
        if(l_parser) { delete l_parser; l_parser = NULL;}
        // -------------------------------------------------
        // set ruleset info
        // -------------------------------------------------
        m_pb->set_ruleset_id("__na__");
        m_pb->set_ruleset_version("__na__");
        // -------------------------------------------------
        // compile
        // -------------------------------------------------
        l_s = m_engine.compile(*m_compiled_config, *m_pb);
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        m_is_initd = true;
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::init(profile &a_profile, bool a_leave_tmp_file)
{
        // -------------------------------------------------
        // *************************************************
        //              M O D S E C U R I T Y
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // generate modsecurity config...
        // -------------------------------------------------
        int32_t l_s;
        std::string *l_str = new std::string();
        l_s = msx_config_generate(*l_str, a_profile);
        if(l_s != WAFLZ_STATUS_OK)
        {
                if(l_str) { delete l_str; l_str = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // write compiled file
        // -------------------------------------------------
        std::string l_tf;
        l_s = write_tmp("modsecurity", l_str->c_str(), l_str->length(), l_tf);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing write_tmp. reason: %s", ns_waflz::get_err_msg());
                return WAFLZ_STATUS_ERROR;
        }
        if(l_str) { delete l_str; l_str = NULL;}
        // -------------------------------------------------
        // load waf
        // -------------------------------------------------
        l_s = init(config_parser::MODSECURITY, l_tf);
        if(l_s != WAFLZ_STATUS_OK)
        {
                WAFLZ_PERROR(m_err_msg, "performing load with file: %s", l_tf.c_str());
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // unlink tmp
        // -------------------------------------------------
        if(a_leave_tmp_file == false)
        {
                errno = 0;
                l_s = unlink(l_tf.c_str());
                if(l_s == -1)
                {
                        // TODO cleanup ???
                        //WAFLZ_PERROR(m_err_msg, "unlinking tmp file: %s", l_tf.c_str());
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------------
        // *************************************************
        //          C O N F I G   U P D A T E S
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // disable rules
        // -------------------------------------------------
        // disable the rules with the given ids
        // -------------------------------------------------
        m_disabled_rule_id_set.clear();
        const waflz_pb::profile &l_profile_pb = *(a_profile.get_pb());
        for(int32_t i_r = 0; i_r < l_profile_pb.disabled_rules_size(); ++i_r)
        {
                if(!l_profile_pb.disabled_rules(i_r).has_rule_id())
                {
                        continue;
                }
                const std::string &l_id = l_profile_pb.disabled_rules(i_r).rule_id();
                m_pb->add_rule_remove_by_id(l_id);
                m_disabled_rule_id_set.insert(l_id);
        }
        // -------------------------------------------------
        // take a custom rule that exists somewhere and
        // include it
        //     "custom_rules": [{
        //         "rule_id": 100,
        //         "description": "this will need to be fleshed out seriously in the future, but the basic idea is that this can hold an abstract representation of a rule, that gets rendered into modsec language as it's loaded."
        //     }]
        // -------------------------------------------------
        // TODO
        // -------------------------------------------------
        // rule target updates
        // -------------------------------------------------
        // update the targets for a given rule
        // "rule_target_updates": [
        //     {
        //         "rule_id": "981172",
        //         "target": "ARGS",
        //         "target_match": "email",
        //         "is_regex": false,
        //         "is_negated": true,
        //         "replace_target": ""
        //     }
        // ]
        // -------------------------------------------------
        // SecRuleUpdateTargetById 958895 !ARGS:email
#if 0
        for(int32_t i_rtu = 0; i_rtu < l_profile_pb.rule_target_updates_size(); ++i_rtu)
        {
                const ::waflz_pb::profile_rule_target_update_t& l_rtu = l_profile_pb.rule_target_updates(i_rtu);
        }
#endif
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::msx_config_generate(std::string &ao_buf, profile &a_profile)
{
#define APPEND_UINT64_VAL(_val) do { \
        char _buf[16];\
        snprintf(_buf, 16, "%lu", _val);\
        ao_buf.append(_buf);\
} while(0)

#define APPEND_UINT_VAL(_val) do { \
        char _buf[16];\
        snprintf(_buf, 16, "%u", _val);\
        ao_buf.append(_buf);\
} while(0)

        if(!m_pb)
        {
                WAFLZ_PERROR(m_err_msg, "pb == NULL");
                return WAFLZ_STATUS_ERROR;
        }
        const ::waflz_pb::profile &l_pb = *(a_profile.get_pb());
        // -------------------------------------------------
        // *************************************************
        // begin compilation
        // *************************************************
        // -------------------------------------------------
        // we want to step through and process
        // in order needed to appear in rendered
        // file
        // -------------------------------------------------
        ao_buf.clear();
        // -------------------------------------------------
        // general settings
        // -------------------------------------------------
        const ::waflz_pb::profile_general_settings_t& l_gs = l_pb.general_settings();
        // "On" -> SecRequestBodyAccess
        if(l_gs.process_request_body())
        {
                ao_buf.append("SecRequestBodyAccess On\n");
        }
        else
        {
                ao_buf.append("SecRequestBodyAccess Off\n");
        }
        ao_buf.append("#--------------\n");
        // general_settings["xml_parser"] == true -> long line
        if(l_gs.xml_parser())
        {
                ao_buf.append("SecRule REQUEST_HEADERS:Content-Type \"(?:text|application)/xml\" ");
                ao_buf.append("\"id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML\"\n");
        }
        ao_buf.append("#--------------\n");
        // -------------------------------------------------
        // default values for a bunch o' things
        // -------------------------------------------------
        // DA TODO:
        // Make these sizes use
        // security.content-length-limit
        // -------------------------------------------------
        ao_buf.append("SecRequestBodyLimit 1073741824\n");
        ao_buf.append("SecRequestBodyNoFilesLimit 1048576\n");
        ao_buf.append("SecRequestBodyInMemoryLimit 131072\n");
        ao_buf.append("SecRequestBodyLimitAction Reject\n");
        ao_buf.append("\n");
        ao_buf.append("SecPcreMatchLimit 1000\n");
        ao_buf.append("SecPcreMatchLimitRecursion 1000\n");
        ao_buf.append("SecRule TX:/^MSC_/ \"!@streq 0\"");
        ao_buf.append("  \"id:'200004',phase:2,t:none,deny,msg:'ModSecurity internal error flagged: %{MATCHED_VAR_NAME}'\"");
        ao_buf.append("\n");
        ao_buf.append("#--------------\n");
        // -------------------------------------------------
        // response body
        // -------------------------------------------------
        if(l_gs.process_response_body())
        {
                ao_buf.append("SecResponseBodyAccess On\n");
        }
        else
        {
                ao_buf.append("SecResponseBodyAccess Off\n");
        }
        ao_buf.append("#--------------\n");

        ao_buf.append("SecResponseBodyMimeType ");
        for(int32_t i_rmt = 0; i_rmt < l_gs.response_mime_types_size(); ++i_rmt)
        {
                // for each response mime type
                ao_buf.append(l_gs.response_mime_types(i_rmt));
                ao_buf.append(" ");
        }
        DEL_LAST_CHAR(ao_buf);
        ao_buf.append("\n");
        ao_buf.append("#--------------\n");
        // -------------------------------------------------
        // audit
        // -------------------------------------------------
        // ao_buf.append("SecAuditLog /tmp/modsec-audit.log\n");
        // ao_buf.append("SecAuditEngine On\n");
        // -------------------------------------------------
        // limits
        // -------------------------------------------------
        ao_buf.append("SecResponseBodyLimit 524288\n");
        ao_buf.append("SecResponseBodyLimitAction ProcessPartial\n");
        ao_buf.append("#--------------\n");
        // DA TODO: Confirm /tmp is ok for mod security to use for data
        //          also test what happens when it fills up
        ao_buf.append("SecTmpDir /tmp/\n");
        ao_buf.append("SecDataDir /tmp/\n");
        ao_buf.append("SecArgumentSeparator &\n");
        ao_buf.append("SecCookieFormat 0\n");
        ao_buf.append("#--------------\n");
        ao_buf.append("SecComponentSignature \"");
        ao_buf.append(l_pb.ruleset_id());
        ao_buf.append("/");
        ao_buf.append(l_pb.ruleset_version());
        ao_buf.append("\"\n");
        ao_buf.append("#--------------\n");
        // -------------------------------------------------
        // engine
        // -------------------------------------------------
        // anomaly engine requires default action is pass
        ao_buf.append("SecDefaultAction \"phase:1,log,pass\"\n");
        ao_buf.append("SecDefaultAction \"phase:2,log,pass\"\n");
        ao_buf.append("#--------------\n");
        // -------------------------------------------------
        // paranoia config
        // -------------------------------------------------
        if(m_owasp_ruleset_version >= 300)
        {
        //default
        uint32_t l_paranoia_level = 1;
        if(l_gs.has_paranoia_level() &&
           (l_gs.paranoia_level() > 0))
        {
                l_paranoia_level = l_gs.paranoia_level();
        }
        ao_buf.append("SecAction \"id:'900000',phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=");
        APPEND_UINT_VAL(l_paranoia_level);
        ao_buf.append("\"\n");
        ao_buf.append("#--------------\n");
        }
        // -------------------------------------------------
        // anomaly settings
        // -------------------------------------------------
        const ::waflz_pb::profile_general_settings_t_anomaly_settings_t& l_ax = l_gs.anomaly_settings();
        ao_buf.append("SecAction \"id:'900001',phase:1,t:none,");
        ao_buf.append("    setvar:tx.critical_anomaly_score=");
        APPEND_UINT_VAL((l_ax.critical_score()));
        ao_buf.append(",");
        ao_buf.append("    setvar:tx.error_anomaly_score=");
        APPEND_UINT_VAL((l_ax.error_score()));
        ao_buf.append(",");
        ao_buf.append("    setvar:tx.warning_anomaly_score=");
        APPEND_UINT_VAL((l_ax.warning_score()));
        ao_buf.append(",");
        ao_buf.append("    setvar:tx.notice_anomaly_score=");
        APPEND_UINT_VAL((l_ax.notice_score()));
        ao_buf.append(",    nolog,pass\"\n");
        ao_buf.append("#--------------\n");
        ao_buf.append("SecAction \"id:'900002',phase:1,t:none,"
                        "    setvar:tx.anomaly_score=0, "
                        "    setvar:tx.sql_injection_score=0, "
                        "    setvar:tx.xss_score=0, "
                        "    setvar:tx.inbound_anomaly_score=0, "
                        "    setvar:tx.outbound_anomaly_score=0, "
                        "    nolog,pass\"\n");
        ao_buf.append("#--------------\n");
        // -------------------------------------------------
        // changing var names depending on ruleset
        // version...
        // OWASP changed from:
        //   inbound_anomaly_score_level
        //   to
        //   outbound_anomaly_score_threshold
        // -------------------------------------------------
        ao_buf.append("SecAction \"id:'900003',phase:1,t:none, ");
        if(m_owasp_ruleset_version >= 300)
        {
        ao_buf.append("    setvar:tx.inbound_anomaly_score_threshold=");
        APPEND_UINT_VAL((l_ax.inbound_threshold()));
        ao_buf.append(",");
        ao_buf.append("    setvar:tx.outbound_anomaly_score_threshold=");
        APPEND_UINT_VAL((l_ax.outbound_threshold()));
        }
        else
        {
        ao_buf.append("    setvar:tx.inbound_anomaly_score_level=");
        APPEND_UINT_VAL((l_ax.inbound_threshold()));
        ao_buf.append(",");
        ao_buf.append("    setvar:tx.outbound_anomaly_score_level=");
        APPEND_UINT_VAL((l_ax.outbound_threshold()));
        }
        ao_buf.append(",    nolog,pass\"\n");
        ao_buf.append("#--------------\n");
        // anomaly engine please
        ao_buf.append("SecAction \"id:'900004',phase:1,t:none,setvar:tx.anomaly_score_blocking=on,nolog,pass\"\n");
        ao_buf.append("#--------------\n");
        // -------------------------------------------------
        // general settings
        // -------------------------------------------------
        ao_buf.append("SecAction \"id:'900006',phase:1,t:none,    setvar:tx.max_num_args=");
        APPEND_UINT_VAL((l_gs.max_num_args()));
        ao_buf.append(",    nolog,pass\"\n");
        ao_buf.append("SecAction \"id:'900007',phase:1,t:none,    setvar:tx.arg_name_length=");
        APPEND_UINT_VAL((l_gs.arg_name_length()));
        ao_buf.append(",    nolog,pass\"\n");
        ao_buf.append("SecAction \"id:'900008',phase:1,t:none,    setvar:tx.arg_length=");
        APPEND_UINT_VAL((l_gs.arg_length()));
        ao_buf.append(",    nolog,pass\"\n");
        ao_buf.append("SecAction \"id:'900009',phase:1,t:none,    setvar:tx.total_arg_length=");
        APPEND_UINT_VAL((l_gs.total_arg_length()));
        ao_buf.append(",    nolog,pass\"\n");
        ao_buf.append("SecAction \"id:'900010',phase:1,t:none,    setvar:tx.max_file_size=");
        APPEND_UINT64_VAL((l_gs.max_file_size()));
        ao_buf.append(",    nolog,pass\"\n");
        ao_buf.append("SecAction \"id:'900011',phase:1,t:none,    setvar:tx.combined_file_sizes=");
        APPEND_UINT64_VAL((l_gs.combined_file_sizes()));
        ao_buf.append(",    nolog,pass\"\n");
        ao_buf.append("#--------------\n");
        // -------------------------------------------------
        // allowed http methods
        // -------------------------------------------------
        ao_buf.append("SecAction \"id:'900012',phase:1,t:none,");
        ao_buf.append("setvar:'tx.allowed_methods=");
        if(!l_gs.allowed_http_methods_size())
        {
                WAFLZ_PERROR(m_err_msg, "No allowed http methods provided.  This will block all traffic.  Not applying.");
                return WAFLZ_STATUS_ERROR;
        }
        for(int32_t i_ahm = 0; i_ahm < l_gs.allowed_http_methods_size(); ++i_ahm)
        {
                // for each allowed http method
                ao_buf.append(l_gs.allowed_http_methods(i_ahm));
                // append space if not last
                if((i_ahm + 1) < l_gs.allowed_http_methods_size())
                {
                        ao_buf.append(" ");
                }
        }
        ao_buf.append("',");
        // -------------------------------------------------
        // allowed_request_content_types
        // -------------------------------------------------
        ao_buf.append("setvar:'tx.allowed_request_content_type=");
        if(!l_gs.allowed_request_content_types_size())
        {
                WAFLZ_PERROR(m_err_msg, "No allowed http request content-types provided.  This is in danger of blocking all traffic.  Not applying.");
                return WAFLZ_STATUS_ERROR;
        }
        for(int32_t i_arct = 0; i_arct < l_gs.allowed_request_content_types_size(); ++i_arct)
        {
                // for each allowed content type
                ao_buf.append(l_gs.allowed_request_content_types(i_arct));
                // append space if not last
                if((i_arct + 1) < l_gs.allowed_request_content_types_size())
                {
                        ao_buf.append("|");
                }
        }
        ao_buf.append("',");
        // -------------------------------------------------
        // allowed_http_versions
        // -------------------------------------------------
        ao_buf.append("   setvar:'tx.allowed_http_versions=HTTP/1.1',");
        // -------------------------------------------------
        // disallowed_extensions
        // -------------------------------------------------
        ao_buf.append("    setvar:'tx.restricted_extensions=");
        for(int32_t i_dx = 0; i_dx < l_gs.disallowed_extensions_size(); ++i_dx)
        {
                // for each allowed http method
                ao_buf.append(l_gs.disallowed_extensions(i_dx));
                // append space if not last
                if((i_dx + 1) < l_gs.disallowed_extensions_size())
                {
                        ao_buf.append("/ ");
                }
        }
        ao_buf.append("',");
        // -------------------------------------------------
        // disallowed_headers
        // -------------------------------------------------
        ao_buf.append("    setvar:'tx.restricted_headers=");
        for(int32_t i_dh = 0; i_dh < l_gs.disallowed_headers_size(); ++i_dh)
        {
                // for each allowed http method
                ao_buf.append("/");
                // ---------------------------------------
                // Due to our customizations to this rule,
                // to get it to actually work properly
                // (See [SECC-115])
                // we need to md5 the headers
                // ---------------------------------------
                std::string l_dh = l_gs.disallowed_headers(i_dh);
                md5_hasher md5_header;
                md5_header.update(l_dh.c_str(), l_dh.length());
                ao_buf.append(md5_header.hash_str());
                // append space if not last
                if((i_dh + 1) < l_gs.disallowed_headers_size())
                {
                        ao_buf.append("/ ");
                }
                else
                {
                        ao_buf.append("/");
                }
        }
        ao_buf.append("',");
        ao_buf.append("    nolog,pass\"\n");
        ao_buf.append("#--------------\n");
        // -------------------------------------------------
        // validate utf8 encoding please
        // -------------------------------------------------
        if(l_gs.validate_utf8_encoding())
        {
                ao_buf.append("SecAction \"id:'900016',phase:1,t:none,");
                ao_buf.append("    setvar:tx.crs_validate_utf8_encoding=1,");
                ao_buf.append("    nolog,pass\"\n");
        }
        ao_buf.append("#--------------\n");
        // -------------------------------------------------
        // xml_parser is on
        // -------------------------------------------------
        if(l_gs.xml_parser())
        {
                // xml_parser is on
                ao_buf.append("SecRule REQUEST_HEADERS:Content-Type \"text/xml\" \"id:'900017',phase:1,t:none,t:lowercase,nolog,pass,chain\"\n");
                ao_buf.append("    SecRule REQBODY_PROCESSOR \"!@streq XML\" \"ctl:requestBodyProcessor=XML\"\n");
        }
        ao_buf.append("#--------------\n");
        // -------------------------------------------------
        // ???
        // -------------------------------------------------
        ao_buf.append("SecRule REQUEST_HEADERS:User-Agent \"^(.*)$\" \"id:'900018',phase:1,t:none,t:sha1,t:hexEncode,"
                        "    setvar:tx.ua_hash=%{matched_var},"
                        "    nolog,pass\"\n"
                        "\n"
                        "SecRule REMOTE_ADDR \"^(.*)$\" \"id:'900019',phase:1,t:none,capture,"
                        "    setvar:tx.real_ip=%{tx.1},"
                        "    nolog,pass\"\n"
                        "SecRule &TX:REAL_IP \"!@eq 0\" \"id:'900020',phase:1,t:none,"
                        "    initcol:global=global,"
                        "    initcol:ip=%{tx.real_ip}_%{tx.ua_hash},"
                        "    nolog,pass\"\n"
                        "SecRule &TX:REAL_IP \"@eq 0\" \"id:'900021',phase:1,t:none,"
                        "    initcol:global=global,"
                        "    initcol:ip=%{remote_addr}_%{tx.ua_hash},"
                        "    setvar:tx.real_ip=%{remote_addr},"
                        "    nolog,pass\"\n");
        ao_buf.append("#--------------\n");
        // -------------------------------------------------
        // The CRS checks the tx.crs_setup_version variable
        // to ensure that the setup has been loaded. If not
        // planning to use this setup template manually set
        // tx.crs_setup_version variable before including
        // the CRS rules/* files.
        //
        // The variable is a numerical representation of the
        // CRS version number.
        // E.g., v3.0.0 is represented as 300.
        // -------------------------------------------------
        ao_buf.append("SecAction \"id:900990, phase:1, nolog, pass, t:none, setvar:tx.crs_setup_version=");
        APPEND_UINT_VAL((m_owasp_ruleset_version));
        ao_buf.append("\"\n");
        ao_buf.append("#--------------\n");
        // -------------------------------------------------
        // conf file functor
        // -------------------------------------------------
        // look at list of config files and strip
        // disabled ones
        // -------------------------------------------------
        class is_conf_file
        {
        public:
                static int compare(const struct dirent* a_dirent)
                {
                        //TRACE("Looking at file: '%s'", a_dirent->d_name);
                        switch (a_dirent->d_name[0])
                        {
                        case 'a' ... 'z':
                        case 'A' ... 'Z':
                        case '0' ... '9':
                        case '_':
                        {
                                // valid path name to consider
                                const char* l_found = NULL;
                                // look for the .conf suffix
                                l_found = ::strcasestr(a_dirent->d_name, ".conf");
                                if(l_found == NULL)
                                {
                                        // not a .conf file
                                        //TRACE("Failed to find .conf suffix");
                                        goto done;
                                }
                                if(::strlen(l_found) != 5)
                                {
                                        // failed to find .conf right at the end
                                        //TRACE("found in the wrong place. %zu", ::strlen(l_found));
                                        goto done;
                                }
                                // we want this file
                                return 1;
                                break;
                        }
                        default:
                                //TRACE("Found invalid first char: '%c'", a_dirent->d_name[0]);
                                goto done;
                        }
done:
                        return 0;
                }
        };
        // -------------------------------------------------
        // construct ruleset dir
        // -------------------------------------------------
        {
        struct dirent** l_conf_list;
        std::string l_ruleset_dir = a_profile.s_ruleset_dir;
        l_ruleset_dir.append(l_pb.ruleset_id());
        l_ruleset_dir.append("/version/");
        l_ruleset_dir.append(l_pb.ruleset_version());
        l_ruleset_dir.append("/policy/");
        // -------------------------------------------------
        // scan ruleset dir
        // -------------------------------------------------
        int l_num_files = -1;
        l_num_files = ::scandir(l_ruleset_dir.c_str(),
                                &l_conf_list,
                                is_conf_file::compare,
                                alphasort);
        if(l_num_files == -1)
        {
                // failed to build the list of directory entries
                WAFLZ_PERROR(m_err_msg, "Failed to compile modsecurity json instance-profile settings.  Reason: failed to scan profile directory: %s: %s", l_ruleset_dir.c_str(), (errno == 0 ? "unknown" : strerror(errno)));
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // include policies
        // -------------------------------------------------
        typedef std::set<std::string> policy_t;
        if(l_pb.policies_size())
        {
                policy_t l_enable_policies = {};
                for(int32_t i_p = 0; i_p < l_pb.policies_size(); ++i_p)
                {
                        l_enable_policies.insert(l_pb.policies(i_p).policy_id());
                }
                for(int32_t i_f = 0; i_f < l_num_files; ++i_f)
                {
                        if(l_enable_policies.find(l_conf_list[i_f]->d_name) != l_enable_policies.end())
                        {
                                ao_buf.append("Include \"");
                                ao_buf.append(l_ruleset_dir);
                                ao_buf.append(l_conf_list[i_f]->d_name);
                                ao_buf.append("\"\n");
                        }
                        if(l_conf_list[i_f])
                        {
                                free(l_conf_list[i_f]);
                                l_conf_list[i_f] = NULL;
                        }
                }
        }
        // -------------------------------------------------
        // exclude policies
        // -------------------------------------------------
        else
        {
                policy_t l_disabled_policies = {};
                for(int32_t i_p = 0; i_p < l_pb.disabled_policies_size(); ++i_p)
                {
                        l_disabled_policies.insert(l_pb.disabled_policies(i_p).policy_id());
                }
                for(int32_t i_f = 0; i_f < l_num_files; ++i_f)
                {
                        if(l_disabled_policies.find(l_conf_list[i_f]->d_name) == l_disabled_policies.end())
                        {
                                ao_buf.append("Include \"");
                                ao_buf.append(l_ruleset_dir);
                                ao_buf.append(l_conf_list[i_f]->d_name);
                                ao_buf.append("\"\n");
                        }
                        if(l_conf_list[i_f])
                        {
                                free(l_conf_list[i_f]);
                                l_conf_list[i_f] = NULL;
                        }
                }
        }
        if(l_conf_list)
        {
                free(l_conf_list);
                l_conf_list = NULL;
        }
        }
        ao_buf.append("#--------------\n");
        // end compilation
        return WAFLZ_STATUS_OK;
}
#if 0
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::init_line(config_parser::format_t a_format, const std::string &a_line)
{
         // Check if already is initd
        if(m_is_initd)
        {
                return WAFLZ_STATUS_OK;
        }
        int32_t l_s;
        // -------------------------------------------------
        // parse
        // -------------------------------------------------
        l_s = m_parser.parse_line(a_format, m_pb, a_line);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error\n");
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // set ruleset info
        // -------------------------------------------------
        m_pb->set_ruleset_id("__na__");
        m_pb->set_ruleset_version("__na__");
        // -------------------------------------------------
        // compile
        // -------------------------------------------------
        l_s = compile();
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        m_is_initd = true;
        return WAFLZ_STATUS_OK;
}
#endif
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::process_rule(waflz_pb::event **ao_event,
                          const waflz_pb::sec_rule_t &a_rule,
                          rqst_ctx &a_ctx)
{
        //NDBG_PRINT("**********************************************\n");
        //NDBG_PRINT("*                 R U L E                     \n");
        //NDBG_PRINT("**********************************************\n");
        //NDBG_PRINT("rule: %s\n", a_rule.ShortDebugString().c_str());
#if 0
        // TODO REMOVE
        {
        std::string l_id = "__na__";
        if(a_rule.action().has_id()) { l_id = a_rule.action().id(); }
        std::string l_msg = "__na__";
        if(a_rule.action().has_msg()) { l_msg = a_rule.action().msg(); }
        NDBG_OUTPUT("XXXXXXX: id: %16s :: msg: %s\n", l_id.c_str(), l_msg.c_str());
        }
#endif
        // -------------------------------------------------
        // check for remove rule id
        // -------------------------------------------------
        if(a_rule.action().has_id() &&
           !m_disabled_rule_id_set.empty() &&
           (m_disabled_rule_id_set.find(a_rule.action().id()) != m_disabled_rule_id_set.end()))
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // chain rule loop
        // -------------------------------------------------
        const waflz_pb::sec_rule_t *l_rule = NULL;
        int32_t l_cr_idx = -1;
        bool i_match = false;
        do {
                //NDBG_PRINT("RULE[%4d]************************************\n", l_cr_idx);
                //NDBG_PRINT("l_cr_idx: %d\n", l_cr_idx);
                if(l_cr_idx == -1)
                {
                        l_rule = &a_rule;
                }
                else if((l_cr_idx >= 0) &&
                        (l_cr_idx < a_rule.chained_rule_size()))
                {
                        l_rule = &(a_rule.chained_rule(l_cr_idx));
                }
                else
                {
                        //WAFLZ_PERROR(m_err_msg, "bad chained rule idx: %d -size: %d",
                        //             l_cr_idx,
                        //             a_rule.chained_rule_size());
                        return WAFLZ_STATUS_ERROR;
                }
                //show_rule_info(a_rule);
                // Get action
                if(!l_rule->has_action())
                {
                        // TODO is OK???
                        ++l_cr_idx;
                        continue;
                }
                //if(l_action.has_id())
                //{
                //        NDBG_PRINT("ID: %16s  ************************\n", l_action.id().c_str());
                //}
                if(!l_rule->has_operator_())
                {
                        // TODO this aight???
                        // TODO is OK???
                        ++l_cr_idx;
                        continue;
                }
                int32_t l_s;
                i_match = false;
                l_s = process_rule_part(ao_event,
                                        i_match,
                                        *l_rule,
                                        a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        //WAFLZ_PERROR(m_err_msg, "bad chained rule idx: %d -size: %d",
                        //             l_cr_idx,
                        //             a_rule.chained_rule_size());
                        return WAFLZ_STATUS_ERROR;
                }
                if(!i_match)
                {
                        // bail out on first un-matched...
                        return WAFLZ_STATUS_OK;
                }
                ++l_cr_idx;
        } while(l_cr_idx < a_rule.chained_rule_size());
        // -------------------------------------------------
        // never matched...
        // -------------------------------------------------
        if(!i_match)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // matched...
        // -------------------------------------------------
        //NDBG_PRINT("%sMATCH%s: !!!\n%s%s%s\n",
        //           ANSI_COLOR_BG_RED, ANSI_COLOR_OFF,
        //           ANSI_COLOR_FG_RED, a_rule.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        if(!a_rule.has_action())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // run disruptive action...
        // -------------------------------------------------
        // TODO !!!
        //NDBG_PRINT("%sACTIONS%s: !!!\n%s%s%s\n",
        //           ANSI_COLOR_BG_MAGENTA, ANSI_COLOR_OFF,
        //           ANSI_COLOR_FG_MAGENTA, a_rule.action().ShortDebugString().c_str(), ANSI_COLOR_OFF);
#if 0
        for(int32_t i_s = 0; i_s < a_rule.action().setvar_size(); ++i_s)
        {
                const ::waflz_pb::sec_action_t_setvar_t& l_sv = a_rule.action().setvar(i_s);
                NDBG_PRINT("%sSET_VAR%s: %s%s%s\n",
                           ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF,
                           ANSI_COLOR_FG_GREEN, l_sv.ShortDebugString().c_str(), ANSI_COLOR_OFF);

        }
#endif
        // -------------------------------------------------
        // process match
        // -------------------------------------------------
#if 0
        {
        std::string l_id = "NA";
        if(a_rule.action().has_id()) { l_id = a_rule.action().id(); }
        std::string l_msg = "NA";
        if(a_rule.action().has_msg()) { l_msg = a_rule.action().msg(); }
        NDBG_OUTPUT("MATCHED: id: %16s :: msg: %s\n", l_id.c_str(), l_msg.c_str());
        }
#endif
        int32_t l_s;
        l_s = process_match(ao_event, a_rule, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                NDBG_PRINT("error processing rule\n");
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::process_rule_part(waflz_pb::event **ao_event,
                               bool &ao_match,
                               const waflz_pb::sec_rule_t &a_rule,
                               rqst_ctx &a_ctx)
{
        macro *l_macro =  &(m_engine.get_macro());
        ao_match = false;
        const waflz_pb::sec_action_t &l_a = a_rule.action();
        bool l_multimatch = l_a.multimatch();
        // -----------------------------------------
        // get operator
        // -----------------------------------------
        if(!a_rule.has_operator_() ||
           !a_rule.operator_().has_type())
        {
                // TODO log error -shouldn't happen???
                return WAFLZ_STATUS_OK;
        }
        const ::waflz_pb::sec_rule_t_operator_t& l_op = a_rule.operator_();
        op_t l_op_cb = NULL;
        l_op_cb = get_op_cb(l_op.type());
        // -----------------------------------------
        // variable loop
        // -----------------------------------------
        uint32_t l_var_count = 0;
        for(int32_t i_var = 0; i_var < a_rule.variable_size(); ++i_var)
        {
                // -----------------------------------------
                // get var cb
                // -----------------------------------------
                const waflz_pb::sec_rule_t_variable_t& l_var = a_rule.variable(i_var);
                if(!l_var.has_type())
                {
                        return WAFLZ_STATUS_OK;
                }
                // Reflect Variable name
                const google::protobuf::EnumValueDescriptor* l_var_desc =
                                waflz_pb::sec_rule_t_variable_t_type_t_descriptor()->FindValueByNumber(l_var.type());
                get_var_t l_get_var = NULL;
                l_get_var = get_var_cb(l_var.type());
                if(!l_get_var)
                {
                        // ---------------------------------
                        // TODO REMOVE
                        // used for development
                        // ---------------------------------
                        a_ctx.m_unimplemented_variables[l_var_desc->name()]++;
                        return WAFLZ_STATUS_OK;
                }
                int32_t l_s;
                const char *l_x_data;
                uint32_t l_x_len;
                // -----------------------------------------
                // extract list of data
                // -----------------------------------------
                const_arg_list_t l_data_list;
                l_s = l_get_var(l_data_list, l_var_count, l_var, &a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                // -----------------------------------------
                // Handle count first
                // -----------------------------------------
                if(l_var.is_count())
                {
                        std::string l_v_c = std::to_string(l_var_count);
                        l_x_data = l_v_c.c_str();
                        l_x_len = l_v_c.length();
                        bool l_match = false;
                        if(!l_op_cb)
                        {
                                continue;
                        }
                        l_s = l_op_cb(l_match, l_op, l_x_data, l_x_len, l_macro, &a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                // TODO log reason???
                                return WAFLZ_STATUS_ERROR;
                        }
                        if(!l_match)
                        {
                                continue;
                        }
                        a_ctx.m_cx_matched_var.assign(l_x_data, l_x_len);
                        a_ctx.m_cx_matched_var_name = l_var_desc->name();
                        ao_match = true;
                        break;
                }
                // -----------------------------------------
                // data loop
                // -----------------------------------------
                for(const_arg_list_t::const_iterator i_v = l_data_list.begin();
                    i_v != l_data_list.end();
                    ++i_v)
                {
                        // ---------------------------------
                        // transformation loop
                        // ---------------------------------
                        // ---------------------------------
                        // Set size to at least one if no tx
                        // specified
                        // ---------------------------------
                        int32_t l_t_size = l_a.t_size() ? l_a.t_size() : 1;
                        l_x_data = i_v->m_val;
                        l_x_len = i_v->m_val_len;
                        bool l_mutated = false;
                        for(int32_t i_t = 0; i_t < l_t_size; ++i_t)
                        {
                                // -------------------------
                                // *************************
                                //           T X
                                // *************************
                                // -------------------------
                                waflz_pb::sec_action_t_transformation_type_t l_t_type = waflz_pb::sec_action_t_transformation_type_t_NONE;
                                if(i_t > 1 ||
                                   l_a.t_size())
                                {
                                        l_t_type = l_a.t(i_t);
                                }
                                if(l_t_type == waflz_pb::sec_action_t_transformation_type_t_NONE)
                                {
                                        goto run_op;
                                }
                                // -------------------------
                                // if tx...
                                // -------------------------
                                {
                                tx_cb_t l_tx_cb = NULL;
                                l_tx_cb = get_tx_cb(l_t_type);
                                if(!l_tx_cb)
                                {
                                        // -----------------
                                        // TODO REMOVE
                                        // used for development
                                        // -----------------
                                        // Reflect Variable name
                                        const google::protobuf::EnumValueDescriptor* l_descriptor =
                                                        waflz_pb::sec_action_t_transformation_type_t_descriptor()->FindValueByNumber(l_t_type);
                                        a_ctx.m_unimplemented_transformations[l_descriptor->name()]++;
                                        continue;
                                }
                                char *l_tx_data = NULL;
                                uint32_t l_tx_len = 0;
                                l_s = l_tx_cb(&l_tx_data, l_tx_len, l_x_data, l_x_len);
                                if(l_s != WAFLZ_STATUS_OK)
                                {
                                        // TODO log reason???
                                        return WAFLZ_STATUS_ERROR;
                                }
                                if(l_mutated)
                                {
                                        free(const_cast <char *>(l_x_data));
                                        l_x_len = 0;
                                        l_mutated = false;
                                }
                                l_mutated = true;
                                l_x_data = l_tx_data;
                                l_x_len = l_tx_len;
                                // -------------------------
                                // break if no data
                                // no point in transforming
                                // or matching further
                                // -------------------------
                                if(!l_x_data ||
                                   !l_x_len)
                                {
                                        break;
                                }
                                }
run_op:
                                // -------------------------
                                // skip op if:
                                // not multimatch
                                // AND
                                // not the end of the list
                                // -------------------------
                                if(!l_multimatch &&
                                   (i_t != (l_t_size - 1)))
                                {
                                        continue;
                                }
                                // -------------------------
                                // *************************
                                //           O P
                                // *************************
                                // -------------------------
                                if(!l_op_cb)
                                {
                                        // -----------------------------------------
                                        // TODO REMOVE
                                        // used for development
                                        // -----------------------------------------
                                        // Reflect Variable name
                                        const google::protobuf::EnumValueDescriptor* l_desc =
                                                        waflz_pb::sec_rule_t_operator_t_type_t_descriptor()->FindValueByNumber(l_op.type());
                                        a_ctx.m_unimplemented_operators[l_desc->name()]++;
                                        // TODO log error -shouldn't happen???
                                        continue;
                                }
                                bool l_match = false;
                                l_s = l_op_cb(l_match, l_op, l_x_data, l_x_len, l_macro, &a_ctx);
                                if(l_s != WAFLZ_STATUS_OK)
                                {
                                        // TODO log reason???
                                        return WAFLZ_STATUS_ERROR;
                                }
                                if(!l_match)
                                {
                                        continue;
                                }
                                a_ctx.m_cx_matched_var.assign(l_x_data, l_x_len);
                                a_ctx.m_cx_matched_var_name = l_var_desc->name();
                                a_ctx.m_cx_matched_var_name += ":";
                                a_ctx.m_cx_matched_var_name.append(i_v->m_key, i_v->m_key_len);
                                //NDBG_PRINT("%sMATCH%s: !!!%s%s%s\n",
                                //           ANSI_COLOR_BG_MAGENTA, ANSI_COLOR_OFF,
                                //           ANSI_COLOR_FG_MAGENTA, a_rule.ShortDebugString().c_str(), ANSI_COLOR_OFF);
                                ao_match = true;
                                break;
                        }
                        // ---------------------------------
                        // final cleanup
                        // ---------------------------------
                        if(l_mutated)
                        {
                                free(const_cast <char *>(l_x_data));
                                l_x_data = NULL;
                                l_x_len = 0;
                                l_mutated = false;
                        }
                        // ---------------------------------
                        // got a match -outtie
                        // ---------------------------------
                        if(ao_match)
                        {
                                break;
                        }
                }
                // -----------------------------------------
                // got a match -outtie
                // -----------------------------------------
                if(ao_match)
                {
                        break;
                }
        }
        // -------------------------------------------------
        // *************************************************
        //                A C T I O N S
        // *************************************************
        // -------------------------------------------------
        if(ao_match)
        {
#define _SET_RULE_INFO(_field, _str) \
if(l_a.has_##_field()) { \
data_t l_k; l_k.m_data = _str; l_k.m_len = sizeof(_str); \
data_t l_v; \
l_v.m_data = l_a._field().c_str(); \
l_v.m_len = l_a._field().length(); \
a_ctx.m_cx_rule_map[l_k] = l_v; \
}
                // -----------------------------------------
                // set rule info
                // -----------------------------------------
                _SET_RULE_INFO(id, "id");
                _SET_RULE_INFO(msg, "msg");
                // -----------------------------------------
                // TODO -only run
                // non-disruptive???
                // -----------------------------------------
                int32_t l_s = process_action_nd(l_a, a_ctx);
                if(l_s == WAFLZ_STATUS_ERROR)
                {
                        NDBG_PRINT("error executing action");
                }
                //NDBG_PRINT("%sACTIONS%s: !!!\n%s%s%s\n",
                //           ANSI_COLOR_BG_CYAN, ANSI_COLOR_OFF,
                //           ANSI_COLOR_FG_CYAN, l_a.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        }
        // -------------------------------------------------
        // null out any set skip values
        // -------------------------------------------------
        else
        {
                a_ctx.m_skip = 0;
                a_ctx.m_skip_after = NULL;
        }
#if 0
        +---------------------------------+----------+
        | Actions                         | Count    |
        +---------------------------------+----------+
        | block                           |      186 |
        | capture                         |      175 |
        | deny                            |        4 |
        | drop                            |        2 |
        | expirevar                       |       16 |
        | nolog                           |      257 |
        | pass                            |      273 |
        | setvar                          |      814 |
        | skip                            |        2 |
        | skipafter                       |      188 |
        +---------------------------------+----------+
#endif
        return WAFLZ_STATUS_OK;
}
/// ----------------------------------------------------------------------------
/// @brief  process the actions in modsec directive or inside a rule
/// @param  a_action, request context
/// @return WAFLZ_STATUS_ERROR or WAFLZ_STATUS_OK
/// ----------------------------------------------------------------------------
int32_t waf::process_action_nd(const waflz_pb::sec_action_t &a_action,
                               rqst_ctx &a_ctx)
{
        // -------------------------------------------------
        // check for skip
        // -------------------------------------------------
        if(a_action.has_skip() &&
           (a_action.skip() > 0))
        {
                a_ctx.m_skip = a_action.skip();
                a_ctx.m_skip_after = NULL;
        }
        // -------------------------------------------------
        // check for skip
        // -------------------------------------------------
        if(a_action.has_skipafter() &&
           !a_action.skipafter().empty())
        {
                a_ctx.m_skip = a_action.skip();
                a_ctx.m_skip_after = a_action.skipafter().c_str();
        }
        // -------------------------------------------------
        // for each var
        // -------------------------------------------------
        macro &l_macro = m_engine.get_macro();
        for(int32_t i_sv = 0; i_sv < a_action.setvar_size(); ++i_sv)
        {
                const ::waflz_pb::sec_action_t_setvar_t& l_sv = a_action.setvar(i_sv);
                //NDBG_PRINT("%ssetvar%s: %s%s%s\n",
                //           ANSI_COLOR_BG_GREEN, ANSI_COLOR_OFF,
                //           ANSI_COLOR_FG_GREEN, l_sv.ShortDebugString().c_str(), ANSI_COLOR_OFF);
                //------------------------------------------
                // var expansion
                //------------------------------------------
                const ::std::string& l_var = l_sv.var();
                const std::string *l_var_ref = &l_var;
                std::string l_sv_var;
                if(l_macro.has(l_var))
                {
                        //NDBG_PRINT("%ssetvar%s: VAR!!!!\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF);
                        int32_t l_s;
                        l_s = l_macro(l_sv_var, l_var, &a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        l_var_ref = &l_sv_var;
                }
                //------------------------------------------
                // val expansion
                //------------------------------------------
                const ::std::string& l_val = l_sv.val();
                const std::string *l_val_ref = &l_val;
                std::string l_sv_val;
                if(l_macro.has(l_val))
                {
                        //NDBG_PRINT("%ssetvar%s: VAL!!!!\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF);
                        int32_t l_s;
                        l_s = l_macro(l_sv_val, l_val, &a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        l_val_ref = &l_sv_val;
                }
                //------------------------------------------
                // *****************************************
                //               S C O P E
                // *****************************************
                //------------------------------------------
                switch(l_sv.scope())
                {
                // -----------------------------------------
                // TX
                // -----------------------------------------
                case ::waflz_pb::sec_action_t_setvar_t_scope_t_TX:
                {
                        cx_map_t &l_cx_map = a_ctx.m_cx_tx_map;
                        //----------------------------------
                        // *********************************
                        //              O P
                        // *********************************
                        //----------------------------------
                        switch(l_sv.op())
                        {
                        //----------------------------------
                        // ASSIGN
                        //----------------------------------
                        case ::waflz_pb::sec_action_t_setvar_t_op_t_ASSIGN:
                        {
                                l_cx_map[*l_var_ref] =  *l_val_ref;
                                break;
                        }
                        //----------------------------------
                        // DELETE
                        //----------------------------------
                        case ::waflz_pb::sec_action_t_setvar_t_op_t_DELETE:
                        {
                                cx_map_t::iterator i_t = l_cx_map.find(*l_var_ref);
                                if(i_t != l_cx_map.end())
                                {
                                        l_cx_map.erase(i_t);
                                }
                                break;
                        }
                        //----------------------------------
                        // INCREMENT
                        //----------------------------------
                        // e.g setvar:tx.rfi_score=+%{tx.critical_anomaly_score}
                        case ::waflz_pb::sec_action_t_setvar_t_op_t_INCREMENT:
                        {
                                int32_t l_pv = 0;
                                cx_map_t::iterator i_t = l_cx_map.find(*l_var_ref);
                                if(i_t != l_cx_map.end())
                                {
                                        l_pv = atoi(i_t->second.c_str());
                                }
                                int32_t l_nv = 0;
                                l_nv = atoi(l_val_ref->c_str());
                                //NDBG_PRINT("INC: var[%s]: %d by: %d\n", l_var_ref->c_str(), l_pv, l_nv);
                                char l_val_str[8];
                                snprintf(l_val_str, 8, "%d", l_pv + l_nv);
                                l_cx_map[*l_var_ref] = l_val_str;
                                break;
                        }
                        //----------------------------------
                        // DECREMENT
                        //----------------------------------
                        case ::waflz_pb::sec_action_t_setvar_t_op_t_DECREMENT:
                        {
                                int32_t l_pv = 0;
                                cx_map_t::iterator i_t = l_cx_map.find(*l_var_ref);
                                if(i_t != l_cx_map.end())
                                {
                                        l_pv = atoi(i_t->second.c_str());
                                }
                                int32_t l_nv = 0;
                                l_nv = atoi(l_val_ref->c_str());
                                char l_val_str[8];
                                snprintf(l_val_str, 8, "%d", l_pv - l_nv);
                                l_cx_map[*l_var_ref] =  l_val_str;
                                break;
                        }
                        //----------------------------------
                        // default
                        //----------------------------------
                        default:
                        {
                                NDBG_PRINT("error invalid op\n");
                                break;
                        }
                        }
                        break;
                }
                // -----------------------------------------
                // IP
                // -----------------------------------------
                case ::waflz_pb::sec_action_t_setvar_t_scope_t_IP:
                {
                        // TODO ???
                        continue;
                }
                default:
                {

                }
                }
        }
        //--------------------------------------------------
        // TODO -remove -for debugging
        //--------------------------------------------------
#if 0
        for(cx_map_t::iterator i_t = a_ctx.m_cx_tx_map.begin();
            i_t != a_ctx.m_cx_tx_map.end();
            ++i_t)
        {
                NDBG_PRINT("TX:: %s --> %s\n", i_t->first.c_str(), i_t->second.c_str());
        }
#endif
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::process_match(waflz_pb::event** ao_event,
                           const waflz_pb::sec_rule_t& a_rule,
                           rqst_ctx& a_ctx)
{
        if(!ao_event ||
           !a_rule.has_action())
        {
                //NDBG_PRINT("missing event or action\n");
                return WAFLZ_STATUS_ERROR;
        }
        const waflz_pb::sec_action_t &l_action = a_rule.action();
        // -------------------------------------------------
        // compare...
        // -------------------------------------------------
        // 1. get "anomaly_score"...
        // 2. get "inbound_anomaly_score_threshold" or "inbound_anomaly_score_level" --> threshold
        // 3. if(l_score >= l_threshold) mark as intercepted...
        // -------------------------------------------------
        cx_map_t::const_iterator i_t;
        int32_t l_anomaly_score = -1;
        // -------------------------------------------------
        // get anomaly score
        // -------------------------------------------------
        i_t = a_ctx.m_cx_tx_map.find("anomaly_score");
        if(i_t == a_ctx.m_cx_tx_map.end())
        {
                return WAFLZ_STATUS_OK;
        }
        l_anomaly_score = atoi(i_t->second.c_str());
        // -------------------------------------------------
        // skip if no anomaly score and
        // w/o action or PASS types...
        // -------------------------------------------------
        if((l_anomaly_score <= 0) &&
           (!l_action.has_action_type() ||
            (l_action.action_type() == ::waflz_pb::sec_action_t_action_type_t_PASS)))
        {
                return WAFLZ_STATUS_OK;
        }
#define _GET_TX_FIELD(_str, _val) do { \
        i_t = a_ctx.m_cx_tx_map.find(_str); \
        if(i_t == a_ctx.m_cx_tx_map.end()) { \
                NDBG_PRINT("rule: %s missing tx field: %s.\n", a_rule.ShortDebugString().c_str(), _str);\
                return WAFLZ_STATUS_ERROR; \
        } \
        _val = atoi(i_t->second.c_str()); \
} while(0)
        // -------------------------------------------------
        // *************************************************
        // handling anomaly mode natively...
        // *************************************************
        // -------------------------------------------------
#ifdef WAFLZ_NATIVE_ANOMALY_MODE
        // -------------------------------------------------
        // get field values...
        // -------------------------------------------------
        int32_t l_threshold = -1;
        if(get_owasp_ruleset_version() >= 300)
        {
        _GET_TX_FIELD("inbound_anomaly_score_threshold", l_threshold);
        }
        else
        {
        _GET_TX_FIELD("inbound_anomaly_score_level", l_threshold);
        }
        //NDBG_PRINT("%sl_anomaly_score%s: %d\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_anomaly_score);
        //NDBG_PRINT("%sl_threshold%s:     %d\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF, l_threshold);
        // -------------------------------------------------
        // check threshold
        // -------------------------------------------------
        if(l_anomaly_score >= l_threshold)
        {
                a_ctx.m_intercepted = true;
        }
#else
        // ---------------------------------
        // handle anomaly mode in ruleset
        // ---------------------------------
        UNUSED(l_threshold);
        // TODO REMOVE
        if(l_action.action_type()) { NDBG_PRINT("action_type: %d\n", l_action.action_type()); }
        if(l_action.has_action_type() &&
           (l_action.action_type() == waflz_pb::sec_action_t_action_type_t_DENY))
        {
                a_ctx.m_intercepted = true;
        }
#endif
        // -------------------------------------------------
        // create info...
        // -------------------------------------------------
        waflz_pb::event* l_sub_event = NULL;
        if(!(*ao_event))
        {
                *ao_event = new ::waflz_pb::event();
        }
        //NDBG_PRINT("%sadd_sub_event%s:\n", ANSI_COLOR_FG_RED, ANSI_COLOR_OFF);
        l_sub_event = (*ao_event)->add_sub_event();
        // -------------------------------------------------
        // populate info
        // -------------------------------------------------
        // -------------------------------------------------
        // msg
        // -------------------------------------------------
        // TODO -expand macros???
        //expand_macros(l_msr, l_var, NULL, a_r.pool);
        //ao_event.set_rule_msg(l_var->value);
        //NDBG_PRINT("l_axnset->msg: %s\n", l_axnset->msg);
        std::string l_msg;
        macro &l_macro = m_engine.get_macro();
        if(l_macro.has(l_action.msg()))
        {
                //NDBG_PRINT("%ssetvar%s: VAL!!!!\n", ANSI_COLOR_BG_RED, ANSI_COLOR_OFF);
                int32_t l_s;
                l_s = l_macro(l_msg, l_action.msg(), &a_ctx);
                if(l_s != WAFLZ_STATUS_OK)
                {
                        return WAFLZ_STATUS_ERROR;
                }
                //NDBG_PRINT("l_msg %s\n", l_msg.c_str());
        }
        if(!l_msg.empty())
        {
                 (*ao_event)->set_rule_msg(l_msg);
                 l_sub_event->set_rule_msg(l_msg);
        }
        else
        {
                if(l_action.has_msg()) { l_sub_event->set_rule_msg(l_action.msg()); }
                (*ao_event)->set_rule_msg(l_action.msg());
        }
        // -------------------------------------------------
        // rule info
        // -------------------------------------------------
        if(l_action.has_id()) { l_sub_event->set_rule_id((uint32_t)atol(l_action.id().c_str())); }
        if(a_rule.operator_().has_type())
        {
                const google::protobuf::EnumValueDescriptor* l_op_desc =
                                        waflz_pb::sec_rule_t_operator_t_type_t_descriptor()->FindValueByNumber(a_rule.operator_().type());
                l_sub_event->set_rule_op_name(l_op_desc->name());
        }
        if(a_rule.operator_().has_value()) { l_sub_event->set_rule_op_param(a_rule.operator_().value()); }
        // -------------------------------------------------
        // tx vars
        // -------------------------------------------------
        int32_t l_sql_injection_score;
        int32_t l_xss_score;
        _GET_TX_FIELD("sql_injection_score", l_sql_injection_score);
        _GET_TX_FIELD("xss_score", l_xss_score);
        l_sub_event->set_total_anomaly_score(l_anomaly_score);
        l_sub_event->set_total_sql_injection_score(l_sql_injection_score);
        l_sub_event->set_total_xss_score(l_xss_score);
        // -------------------------------------------------
        // rule targets
        // -------------------------------------------------
        //NDBG_PRINT("rule matched %s\n", a_rule.DebugString().c_str());
        for(int32_t i_k = 0; i_k < a_rule.variable_size(); ++i_k)
        {
                const waflz_pb::sec_rule_t_variable_t &l_var = a_rule.variable(i_k);
                const google::protobuf::EnumValueDescriptor* l_var_desc =
                                       waflz_pb::sec_rule_t_variable_t_type_t_descriptor()->FindValueByNumber(l_var.type());
                waflz_pb::event::var_t *l_mvar = NULL;
                l_mvar = l_sub_event->add_rule_target();
                // -----------------------------------------
                // counting???
                // -----------------------------------------
                if(l_var.has_is_count() &&
                   l_var.is_count())
                {
                        l_mvar->set_is_counting(true);
                }
                // -----------------------------------------
                // no match info
                // -----------------------------------------
                if(l_var.match_size() <= 0)
                {
                        l_mvar->set_name(l_var_desc->name());
                        continue;
                }
                // -----------------------------------------
                // for each match...
                // -----------------------------------------
                for(int32_t i_m = 0; i_m < l_var.match_size(); ++i_m)
                {
                        // ---------------------------------
                        // name
                        // ---------------------------------
                        l_mvar->set_name(l_var_desc->name());
                        // ---------------------------------
                        // value
                        // ---------------------------------
                        const waflz_pb::sec_rule_t_variable_t_match_t &l_match = l_var.match(i_m);
                        if(!l_match.value().empty())
                        {
                                // -------------------------
                                // fix up string to indicate
                                // is regex
                                // -------------------------
                                std::string l_val = l_match.value();
                                if(l_match.is_regex())
                                {
                                        l_val.insert(0, "/");
                                        l_val += "/";
                                }
                                l_mvar->set_param(l_val);
                        }
                        // ---------------------------------
                        // negated???
                        // ---------------------------------
                        if(l_match.is_negated())
                        {
                                l_mvar->set_is_negated(true);
                        }
                }
        }
        // -------------------------------------------------
        // rule tags
        // -------------------------------------------------
        for(int32_t i_a = 0; i_a < l_action.tag_size(); ++i_a)
        {
                l_sub_event->add_rule_tag(l_action.tag(i_a));
        }
        // -------------------------------------------------
        // intercept status
        // -------------------------------------------------
        l_sub_event->set_rule_intercept_status(403);
        // -------------------------------------------------
        // waf config specifics
        // -------------------------------------------------
        l_sub_event->set_waf_profile_id(m_id);
        l_sub_event->set_waf_profile_name(m_name);
        // -------------------------------------------------
        // check for no log
        // -------------------------------------------------
        if(m_no_log_matched)
        {
                return WAFLZ_STATUS_OK;
        }
#define CAP_LEN(_len) (_len > 1024 ? 1024: _len)
        waflz_pb::event::var_t* l_m_var = NULL;
        // -------------------------------------------------
        // matched var
        // -------------------------------------------------
        l_m_var = l_sub_event->mutable_matched_var();
        l_m_var->set_name(a_ctx.m_cx_matched_var_name);
        if(l_action.sanitisematched())
        {
                l_m_var->set_value("**SANITIZED**");
        }
        else
        {
                l_m_var->set_value(a_ctx.m_cx_matched_var.c_str(), CAP_LEN(a_ctx.m_cx_matched_var.length()));
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::process_phase(waflz_pb::event **ao_event,
                           const directive_list_t &a_dl,
                           const marker_map_t &a_mm,
                           rqst_ctx &a_ctx)
{
        for(directive_list_t::const_iterator i_d = a_dl.begin();
            i_d != a_dl.end();
            ++i_d)
        {
                if(!(*i_d))
                {
                        //NDBG_PRINT("SKIPPING\n");
                        continue;
                }
                // -----------------------------------------
                // marker
                // -----------------------------------------
                const ::waflz_pb::directive_t& l_d = **i_d;
                if(l_d.has_marker())
                {
                        //NDBG_PRINT("%sMARKER%s: %s%s%s\n",
                        //           ANSI_COLOR_BG_RED, ANSI_COLOR_OFF,
                        //           ANSI_COLOR_BG_RED, l_d.marker().c_str(), ANSI_COLOR_OFF);
                        continue;
                }
                // -----------------------------------------
                // action
                // -----------------------------------------
                if(l_d.has_sec_action())
                {
                        const waflz_pb::sec_action_t &l_a = l_d.sec_action();
#if 0
                        // TODO REMOVE
                        {
                        std::string l_id = "__na__";
                        if(l_a.has_id()) { l_id = l_a.id(); }
                        std::string l_msg = "__na__";
                        if(l_a.has_msg()) { l_msg = l_a.msg(); }
                        NDBG_OUTPUT("XXXXXXX: id: %16s :: msg: %s\n", l_id.c_str(), l_msg.c_str());
                        }
#endif
                        //NDBG_PRINT("action: %s\n", l_a.ShortDebugString().c_str());
                        int32_t l_s = process_action_nd(l_a, a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                NDBG_PRINT("error processing rule\n");
                        }
                        continue;
                }
                // -----------------------------------------
                // rule
                // -----------------------------------------
                if(l_d.has_sec_rule())
                {
                        const waflz_pb::sec_rule_t &l_r = l_d.sec_rule();
                        if(!l_r.has_action())
                        {
                                //NDBG_PRINT("error no action for rule: %s\n", l_r.ShortDebugString().c_str());
                                continue;
                        }
                        int32_t l_s;
                        l_s = process_rule(ao_event, l_r, a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                //NDBG_PRINT("error...\n");
                                return WAFLZ_STATUS_ERROR;
                        }
                }
                // -----------------------------------------
                // break if intercepted
                // -----------------------------------------
                if(a_ctx.m_intercepted)
                {
                        break;
                }
                // -----------------------------------------
                // handle skip
                // -----------------------------------------
                if(a_ctx.m_skip)
                {
                        //NDBG_PRINT("%sskipping%s...: %d\n", ANSI_COLOR_BG_YELLOW, ANSI_COLOR_OFF, a_ctx.m_skip);
                        while(a_ctx.m_skip &&
                              (i_d != a_dl.end()))
                        {
                                ++i_d;
                                --a_ctx.m_skip;
                        }
                        a_ctx.m_skip = 0;
                }
                else if(a_ctx.m_skip_after)
                {
                        //NDBG_PRINT("%sskipping%s...: %s\n", ANSI_COLOR_BG_YELLOW, ANSI_COLOR_OFF, a_ctx.m_skip_after);
                        marker_map_t::const_iterator i_nd;
                        i_nd = a_mm.find(a_ctx.m_skip_after);
                        if(i_nd != a_mm.end())
                        {
                                i_d = i_nd->second;
                        }
                        a_ctx.m_skip_after = NULL;
                }
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int32_t waf::process(waflz_pb::event **ao_event, void *a_ctx)
{
        //int32_t l_s = WAFLZ_STATUS_OK;
        if(!m_pb)
        {
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // get rqst_ctx
        // -------------------------------------------------
        int32_t l_s;
        // get body size max
        uint32_t l_body_size_max = DEFAULT_BODY_SIZE_MAX;
        if(m_pb->has_request_body_in_memory_limit())
        {
                l_body_size_max = m_pb->request_body_in_memory_limit();
        }
        rqst_ctx *l_ctx = new rqst_ctx(l_body_size_max);
        // -------------------------------------------------
        // *************************************************
        //                 P H A S E  1
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        l_s = l_ctx->init_phase_1(a_ctx,
                                  m_il_query,
                                  m_il_header,
                                  m_il_cookie);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                NDBG_PRINT("error init_phase_1\n");
                if(l_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // process
        // -------------------------------------------------
        l_s = process_phase(ao_event,
                            m_compiled_config->m_directive_list_phase_1,
                            m_compiled_config->m_marker_map_phase_1,
                            *l_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                NDBG_PRINT("error process_phase\n");
                if(l_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // *************************************************
        //                 P H A S E  2
        // *************************************************
        // -------------------------------------------------
        // -------------------------------------------------
        // init
        // -------------------------------------------------
        l_s = l_ctx->init_phase_2(m_ctype_parser_map, a_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                NDBG_PRINT("error init_phase_2\n");
                if(l_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // process
        // -------------------------------------------------
        l_s = process_phase(ao_event,
                            m_compiled_config->m_directive_list_phase_2,
                            m_compiled_config->m_marker_map_phase_2,
                            *l_ctx);
        if(l_s != WAFLZ_STATUS_OK)
        {
                // TODO -log error???
                NDBG_PRINT("error process_phase\n");
                if(l_ctx) { delete l_ctx; l_ctx = NULL;}
                return WAFLZ_STATUS_ERROR;
        }
        // -------------------------------------------------
        // check for intercepted...
        // -------------------------------------------------
        if(l_ctx->m_intercepted)
        {
                if(*ao_event)
                {
                        // ---------------------------------
                        // add rqst info
                        // ---------------------------------
                        waflz_pb::event &l_event = **ao_event;
                        int32_t l_s;
                        l_s = append_rqst_info(l_event, a_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                NDBG_PRINT("error...\n");
                                return WAFLZ_STATUS_ERROR;
                        }
                        // ---------------------------------
                        // add meta
                        // ---------------------------------
                        // ---------------------------------
                        // *********************************
                        // handling anomaly mode natively...
                        // *********************************
                        // ---------------------------------
#ifdef WAFLZ_NATIVE_ANOMALY_MODE
                        l_event.set_rule_id(981176);
                        const char l_msg_macro[] = "Inbound Anomaly Score Exceeded (Total Score: %{TX.ANOMALY_SCORE}, SQLi=%{TX.SQL_INJECTION_SCORE}, XSS=%{TX.XSS_SCORE}): Last Matched Message: %{tx.msg}";
                        std::string l_msg;
                        macro *l_macro =  &(m_engine.get_macro());
                        l_s = (*l_macro)(l_msg, l_msg_macro, l_ctx);
                        if(l_s != WAFLZ_STATUS_OK)
                        {
                                return WAFLZ_STATUS_ERROR;
                        }
                        l_event.set_rule_msg(l_msg);
#endif
                        l_event.set_waf_profile_id(m_id);
                        l_event.set_waf_profile_name(m_name);
                        // ---------------------------------
                        // add info from last subevent...
                        // ---------------------------------
                        // TODO -should we???
                        //      -seems redundant
                        // ---------------------------------
                        if(l_event.sub_event_size())
                        {
                                const ::waflz_pb::event& l_se = l_event.sub_event(l_event.sub_event_size() - 1);
                                // -------------------------
                                // rule target...
                                // -------------------------
                                ::waflz_pb::event_var_t* l_ev = l_event.add_rule_target();
                                l_ev->set_name("TX");
                                l_ev->set_param("ANOMALY_SCORE");
                                // -------------------------
                                // rule tag...
                                // -------------------------
                                l_event.add_rule_tag()->assign("OWASP_CRS/ANOMALY/EXCEEDED");
                                // -------------------------
                                // matched_var...
                                // -------------------------
                                if(l_se.has_matched_var())
                                {
                                        l_event.mutable_matched_var()->CopyFrom(l_se.matched_var());
                                }
                                // -------------------------
                                // op
                                // -------------------------
                                l_event.mutable_rule_op_name()->assign("gt");
                                l_event.mutable_rule_op_param()->assign("0");
                        }
#define _SET_IF_EXIST(_str, _field) do { \
        if(l_ctx->m_cx_tx_map.find(_str) != l_ctx->m_cx_tx_map.end()) \
        { l_event.set_##_field((uint32_t)(strtoul(l_ctx->m_cx_tx_map[_str].c_str(), NULL, 10))); } \
        else { l_event.set_##_field(0); } \
} while(0)
                        _SET_IF_EXIST("ANOMALY_SCORE", total_anomaly_score);
                        _SET_IF_EXIST("SQL_INJECTION_SCORE", total_sql_injection_score);
                        _SET_IF_EXIST("XSS_SCORE", total_xss_score);
                }
        }
        // TODO -remove! -debugging
        //l_ctx->show_debug();
        // -------------------------------------------------
        // cleanup
        // -------------------------------------------------
        if(l_ctx) { delete l_ctx; l_ctx = NULL;}
        return WAFLZ_STATUS_OK;
}
}
