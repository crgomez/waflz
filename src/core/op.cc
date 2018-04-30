//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wafl.cc
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
#include "waflz/def.h"
#include "rule.pb.h"
#include "core/op.h"
#include "core/macro.h"
#include "core/decode.h"
#include "support/string_util.h"
#include "support/ndebug.h"
#include "op/regex.h"
#include "op/ac.h"
#include "op/byte_range.h"
#include "op/luhn.h"
#include "libinjection/src/libinjection.h"
#include <string.h>
#include <map>
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#define SET_IF_NEGATED() do { \
        if(a_op.has_is_negated() && \
           a_op.is_negated()) { \
                ao_match = !ao_match; \
        } } while(0)
#define EXPAND_MACRO(_val) \
        const std::string *l_val_ref = &l_val; \
        std::string l_sv_var; \
        if(a_macro->has(l_val)) { \
                int32_t l_s = (*a_macro)(l_sv_var, l_val, a_ctx); \
                if(l_s != WAFLZ_STATUS_OK) { return WAFLZ_STATUS_ERROR; } \
                l_val_ref = &l_sv_var; \
        }
#define VALID_HEX(X) \
        (((X >= '0') && (X <= '9')) || \
         ((X >= 'a') && (X <= 'f')) || \
         ((X >= 'A') && (X <= 'F')))
//: ----------------------------------------------------------------------------
//: op macro
//: ----------------------------------------------------------------------------
#define OP(_type) \
        static int32_t _op_cb_##_type(bool& ao_match, \
                                      const waflz_pb::sec_rule_t_operator_t& a_op, \
                                      const char* a_buf, \
                                      const uint32_t& a_len, \
                                      macro* a_macro, \
                                      rqst_ctx *a_ctx)
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: ****************************************************************************
//:                             O P E R A T I O N S
//: ****************************************************************************
//: ----------------------------------------------------------------------------
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(EQ)
{
        ao_match = false;
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // convert/compare
        // -------------------------------------------------
        // atoi -not safe!!!
        int32_t l_in_val;
        l_in_val = atoi(a_buf);
        int32_t l_op_val;
        l_op_val = atoi(l_val_ref->c_str());
        if(l_op_val == l_in_val)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(GE)
{
        ao_match = false;
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // convert/compare
        // -------------------------------------------------
        // atoi -not safe!!!
        int32_t l_in_val;
        l_in_val = atoi(a_buf);
        int32_t l_op_val;
        l_op_val = atoi(l_val_ref->c_str());
        if(l_in_val >= l_op_val)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(GT)
{
        ao_match = false;
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // convert/compare
        // -------------------------------------------------
        // atoi -not safe!!!
        int32_t l_in_val;
        l_in_val = atoi(a_buf);
        int32_t l_op_val;
        l_op_val = atoi(l_val_ref->c_str());
        if(l_in_val > l_op_val)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(CONTAINS)
{
        ao_match = false;
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // find
        // -------------------------------------------------
        if(l_val_ref->length() > a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        char *l_match = NULL;
        l_match = strnstr(a_buf, l_val_ref->c_str(), a_len);
        if(l_match)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(BEGINSWITH)
{
        ao_match = false;
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // find
        // -------------------------------------------------
        uint32_t l_op_val_len = l_val_ref->length();
        if(l_op_val_len > a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        int32_t l_s;
        l_s = memcmp(l_val_ref->c_str(), a_buf, l_op_val_len);
        if(l_s == 0)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(ENDSWITH)
{
        ao_match = false;
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // find
        // -------------------------------------------------
        uint32_t l_op_val_len = l_val_ref->length();
        if(l_op_val_len > a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        int32_t l_s;
        l_s = memcmp(l_val_ref->c_str(), (a_buf + (a_len - l_op_val_len)), l_op_val_len);
        if(l_s == 0)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(STREQ)
{
        ao_match = false;
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // find
        // -------------------------------------------------
        if(l_val_ref->length() != a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        int32_t l_s;
        l_s = strncmp(l_val_ref->c_str(), a_buf, l_val_ref->length());
        if(l_s == 0)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(STRMATCH)
{
        ao_match = false;
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // find
        // -------------------------------------------------
        const std::string &l_val = a_op.value();
        uint32_t l_min = l_val.length() > a_len ? a_len : l_val.length();
        char *l_match = NULL;
        l_match = strnstr(l_val.c_str(), a_buf, l_min);
        if(l_match)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(WITHIN)
{
        ao_match = false;
        if(!a_op.has_value())
        {
                return WAFLZ_STATUS_OK;
        }
        const std::string &l_val = a_op.value();
        EXPAND_MACRO(l_val);
        // -------------------------------------------------
        // find
        // -------------------------------------------------
        if(l_val_ref->length() < a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        char *l_match = NULL;
        l_match = strnstr(l_val_ref->c_str(), a_buf, l_val_ref->length());
        if(l_match)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(PM)
{
        //NDBG_PRINT("a_op: %s%s%s\n", ANSI_COLOR_FG_GREEN, a_op.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        ao_match = false;
        if(!a_op.has__reserved_1() &&
           a_op._reserved_1())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // ac find
        // -------------------------------------------------
        ac *l_ac = (ac *)(a_op._reserved_1());
        bool l_match = false;
        l_match = l_ac->find_first(a_buf, a_len);
        if(l_match)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(PMF)
{
        //NDBG_PRINT("a_op: %s%s%s\n", ANSI_COLOR_FG_GREEN, a_op.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        ao_match = false;
        if(!a_op.has__reserved_1() &&
           a_op._reserved_1())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // ac find
        // -------------------------------------------------
        ac *l_ac = (ac *)(a_op._reserved_1());
        bool l_match = false;
        l_match = l_ac->find_first(a_buf, a_len);
        if(l_match)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(PMFROMFILE)
{
        //NDBG_PRINT("a_op: %s%s%s\n", ANSI_COLOR_FG_GREEN, a_op.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        ao_match = false;
        if(!a_op.has__reserved_1() &&
           a_op._reserved_1())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // ac find
        // -------------------------------------------------
        ac *l_ac = (ac *)(a_op._reserved_1());
        bool l_match = false;
        l_match = l_ac->find_first(a_buf, a_len);
        if(l_match)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(RX)
{
        ao_match = false;
        if(!a_op.has__reserved_1() &&
           a_op._reserved_1())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // regex match...
        // -------------------------------------------------
        regex *l_rx = (regex *)(a_op._reserved_1());
        int32_t l_s;
        // get capture
        data_list_t l_data_list;
        std::string l_capture;
        l_s = l_rx->compare_all(a_buf, a_len, &l_data_list);
        if(l_s > 0)
        {
                int l_index = 0;
                // -------------------------------------------------
                // save matches...
                // -------------------------------------------------
                for(data_list_t::iterator i_d = l_data_list.begin();
                    i_d != l_data_list.end();
                    ++i_d)
                {
                        l_capture.assign((*i_d).m_data, (*i_d).m_len);
                        a_ctx->m_cx_tx_map[std::to_string(l_index)] = l_capture;
                        //NDBG_PRINT("setting TX.%d = %s\n", l_index, l_capture.c_str());
                        ++l_index;
                }
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(VALIDATEURLENCODING)
{
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // validate encoding...
        // -------------------------------------------------
        uint32_t i_c = 0;
        while(i_c < a_len)
        {
                if (a_buf[i_c] != '%')
                {
                        ++i_c;
                        continue;
                }
                // -----------------------------------------
                // check for length
                // -----------------------------------------
                if((i_c + 2) >= a_len)
                {
                        // ---------------------------------
                        // invalid url encoding:
                        // not enough chars
                        // ---------------------------------
                        ao_match = true;
                        return WAFLZ_STATUS_OK;
                }
                // -----------------------------------------
                // decode a %xx combination if it is valid
                // -----------------------------------------
                char l_c1 = a_buf[i_c + 1];
                char l_c2 = a_buf[i_c + 2];
                if(!VALID_HEX(l_c1) ||
                   !VALID_HEX(l_c2))
                {
                        // ---------------------------------
                        // invalid url encoding:
                        // non-hex char used in encoding.
                        // ---------------------------------
                        ao_match = true;
                        return WAFLZ_STATUS_OK;
                }
                i_c += 3;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(VALIDATEBYTERANGE)
{
        //NDBG_PRINT("a_op: %s%s%s\n", ANSI_COLOR_FG_GREEN, a_op.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        if(!a_op.has__reserved_1() &&
           a_op._reserved_1())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // byte range check
        // -------------------------------------------------
        ao_match = false;
        byte_range *l_br = (byte_range *)(a_op._reserved_1());
        bool l_is_in = false;
        l_is_in = l_br->is_within(a_buf, a_len);
        if(!l_is_in)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(VALIDATEUTF8ENCODING)
{
        //NDBG_PRINT("a_op: %s%s%s\n", ANSI_COLOR_FG_GREEN, a_op.ShortDebugString().c_str(), ANSI_COLOR_OFF);
        if(!a_buf ||
           !a_len)
        {
                return WAFLZ_STATUS_OK;
        }
        ao_match = false;
        // -------------------------------------------------
        // utf8 encoding check
        // -------------------------------------------------
        bool l_valid = true;
        const char *l_err = NULL;
        uint32_t l_err_off = 0;
        int32_t l_s;
        l_s = validate_utf8(l_valid, &l_err, l_err_off, a_buf, a_len);
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        if(!l_valid)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(VERIFYCC)
{
        ao_match = false;
        if(!a_op.has__reserved_1() &&
           a_op._reserved_1())
        {
                return WAFLZ_STATUS_OK;
        }
        // -------------------------------------------------
        // regex match...
        // -------------------------------------------------
        regex *l_rx = (regex *)(a_op._reserved_1());
        int32_t l_s;
        // get capture
        data_list_t l_data_list;
        std::string l_match_str;
        l_s = l_rx->compare(a_buf, a_len, &l_match_str);
        // -------------------------------------------------
        // if not match -done...
        // -------------------------------------------------
        if(l_s <= 0)
        {
                SET_IF_NEGATED();
                return WAFLZ_STATUS_OK;
        }
        bool l_cc_valid = false;
        //NDBG_PRINT("CC: check string: %s\n", l_match_str.c_str());
        l_cc_valid = luhn_validate(l_match_str.c_str(), l_match_str.length());
        // -------------------------------------------------
        // if match store result in TX:1
        // modsecurity behavior...
        // -------------------------------------------------
        if(l_cc_valid)
        {
                a_ctx->m_cx_tx_map["1"] = l_match_str;
                ao_match = true;
        }
        //NDBG_PRINT("CC: check status: %d\n", l_cc_valid);
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(DETECTSQLI)
{
        ao_match = false;
        char l_fprnt[8];
        int32_t l_match = 0;
        l_match = libinjection_sqli(a_buf, a_len, l_fprnt);
        if(l_match)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
OP(DETECTXSS)
{
        ao_match = false;
        int32_t l_match = 0;
        l_match = libinjection_xss(a_buf, a_len);
        if(l_match)
        {
                ao_match = true;
        }
        SET_IF_NEGATED();
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: macros
//: ----------------------------------------------------------------------------
#define INIT_OP_CB(_type) \
        s_op_cb_vector[waflz_pb::sec_rule_t_operator_t_type_t_##_type] = _op_cb_##_type

//: ----------------------------------------------------------------------------
//: types
//: ----------------------------------------------------------------------------
typedef std::vector <op_t> op_cb_vector_t;
//: ----------------------------------------------------------------------------
//: vector...
//: ----------------------------------------------------------------------------
static op_cb_vector_t s_op_cb_vector = op_cb_vector_t(1024);
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void init_op_cb_vector(void)
{
        INIT_OP_CB(BEGINSWITH);
        INIT_OP_CB(CONTAINS);
        INIT_OP_CB(DETECTSQLI);
        INIT_OP_CB(DETECTXSS);
        INIT_OP_CB(ENDSWITH);
        INIT_OP_CB(EQ);
        INIT_OP_CB(GE);
        INIT_OP_CB(GT);
        INIT_OP_CB(PM);
        INIT_OP_CB(PMF);
        INIT_OP_CB(PMFROMFILE);
        INIT_OP_CB(RX);
        INIT_OP_CB(STREQ);
        INIT_OP_CB(STRMATCH);
        INIT_OP_CB(VERIFYCC);
        INIT_OP_CB(VALIDATEBYTERANGE);
        INIT_OP_CB(VALIDATEUTF8ENCODING);
        INIT_OP_CB(VALIDATEURLENCODING);
        INIT_OP_CB(WITHIN);
};
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
op_t get_op_cb(waflz_pb::sec_rule_t_operator_t_type_t a_type)
{
        return s_op_cb_vector[a_type];
}
}
