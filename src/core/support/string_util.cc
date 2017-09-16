//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    string_util.cc
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    03/09/2017
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
#include "support/string_util.h"
#include "support/ndebug.h"
#include "waflz/def.h"
#include <limits.h>
#include <string.h>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
std::string get_file_wo_path(const std::string &a_filename)
{
        std::string fName(a_filename);
        size_t pos = fName.rfind("/");

        if(pos == std::string::npos)  //No extension.
                return fName;
        if(pos == 0)    //. is at the front. Not an extension.
                return fName;

        return fName.substr(pos + 1, fName.length());
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
std::string get_file_path(const std::string &a_filename)
{
        std::string fName(a_filename);
        size_t pos = fName.rfind("/");

        if(pos == std::string::npos)  //No extension.
                return fName;
        if(pos == 0)    //. is at the front. Not an extension.
                return fName;

        return fName.substr(0, pos);
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
std::string get_base_filename(const std::string &a_filename)
{
        std::string fName(a_filename);
        size_t pos = fName.rfind(".");

        if(pos == std::string::npos)  //No extension.
                return fName;
        if(pos == 0)    //. is at the front. Not an extension.
                return fName;

        return fName.substr(0, pos);
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
std::string get_file_ext(const std::string &a_filename)
{
        std::string fName(a_filename);
        size_t pos = fName.rfind(".");

        if(pos == std::string::npos)  //No extension.
                return NULL;
        if(pos == 0)    //. is at the front. Not an extension.
                return NULL;

        return fName.substr(pos + 1, fName.length());
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
std::string get_file_wo_ext(const std::string &a_filename)
{
        std::string fName(a_filename);
        size_t pos = fName.rfind(".");

        if(pos == std::string::npos)  //No extension.
                return NULL;
        if(pos == 0)    //. is at the front. Not an extension.
                return NULL;

        return fName.substr(0, pos);
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return: TODO
//: \param:  TODO
//: ----------------------------------------------------------------------------
int32_t convert_hex_to_uint(uint64_t &ao_val, const char *a_str)
{
        ao_val = strtoull(a_str, NULL, 16);
        if((ao_val == ULLONG_MAX) ||
           (ao_val == 0))
        {
                ao_val = 0;
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details parse cookie string:
//:          format: 'key1=val1; key2; key3=val3; key4\0'
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
static bool is_char_in_set(const char *a_arr, uint32_t a_arr_len, char a_char)
{
        for(uint32_t i_c = 0; i_c < a_arr_len; ++i_c)
        {
                if(a_char == a_arr[i_c]) return true;
        }
        return false;
}
//: ----------------------------------------------------------------------------
//: \details parse cookie string:
//:          format: 'key1=val1; key2; key3=val3; key4\0'
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t parse_cookie_str(kv_map_list_t &ao_cookie_map,
                         const char *a_cookie_str,
                         uint32_t a_cookie_str_len)
{
        static const char l_del_set[]    = {'=',';',' ','\t','\f','\r','\n'};
        static const char l_valdel_set[] = {'=',' ','\t','\f','\r','\n'};
        // -------------------------------------------------
        // Parsing logic
        // -------------------------------------------------
        // 1: Skip delimiters
        // 2: Match until ';' or '\0' for key
        // 3: If '=' found, skip to first non-delimiter char
        // 4: Look for value until either ';' or '\0'
        // 5: Back to step 1
        // Example 'cookie: abc= =123  ;def;;;'
        //  - key='abc', val='123'
        //  - key='def', val=''
        // RFC: http://tools.ietf.org/html/rfc6265#section-4.1
        // -------------------------------------------------
        // TODO !!!
        // trim trailing whitespace(s) from values...
        // in ex above -cookie split results in
        //  - key='abc', val='123  '
        // -------------------------------------------------
        // start at first non-delimiter char
        // -------------------------------------------------
        const char *l_key = a_cookie_str;
        const char *l_val=NULL;
        const char *l_keyend=NULL;
        //NDBG_PRINT("SKIP l_del_chars\n");
        for(; is_char_in_set(l_del_set, sizeof(l_del_set), *l_key); ++l_key) {}
        if (*l_key == '\0') return WAFLZ_STATUS_OK;
        //NDBG_PRINT("l_key: %s\n", l_key);
        // -------------------------------------------------
        // NOTE: assume \0 terminated string
        // -------------------------------------------------
        for(const char* i_p = l_key + 1; ; ++i_p)
        {
                //NDBG_PRINT("i_p: %s\n", i_p);
                switch (*i_p)
                {
                // -----------------------------------------
                // \0
                // -----------------------------------------
                case '\0':
                {
                        if(l_val)
                        {
                                // we got "key=value; "
                                std::string l_key_str;
                                l_key_str.append(l_key, (int)(l_keyend - l_key));
                                std::string l_val_str;
                                int l_len = (int)(i_p - l_val);
                                const char *l_p_i = i_p - 1;
                                while(l_len && *l_p_i == ' ') { --l_len; --l_p_i; }
                                l_val_str.append(l_val, l_len);
                                //NDBG_PRINT("l_key: \"%s\"\n", l_key_str.c_str());
                                //NDBG_PRINT("l_val: \"%s\"\n", l_val_str.c_str());
                                kv_map_list_insert(ao_cookie_map, l_key_str, l_val_str);
                        }
                        else
                        {
                                // we got a key with no value
                                std::string l_key_str;
                                l_key_str.append(l_key, (int)(i_p - l_key));
                                std::string l_val_str;
                                kv_map_list_insert(ao_cookie_map, l_key_str, l_val_str);
                        }
                        return WAFLZ_STATUS_OK;
                }
                // -----------------------------------------
                // =
                // -----------------------------------------
                case '=':
                {
                        if (l_val) break;
                        // ---------------------------------
                        // mark end of key and jump to
                        // next non-delimiter character
                        // ---------------------------------
                        l_keyend = i_p++;
                        //NDBG_PRINT("SKIP l_valdel_chars\n");
                        for(; is_char_in_set(l_valdel_set, sizeof(l_valdel_set), *i_p); ++i_p) {}
                        if (*i_p == '\0') return WAFLZ_STATUS_OK;
                        if (*i_p != ';')
                        {
                                l_val = i_p;
                                break;
                        }
                        // fall-thru
                }
                // -----------------------------------------
                // ;
                // -----------------------------------------
                case ';':
                {
                        if(l_val)
                        {
                                // we got "key=value;"
                                std::string l_key_str;
                                l_key_str.append(l_key, (int)(l_keyend - l_key));
                                std::string l_val_str;
                                int l_len = (int)(i_p - l_val);
                                const char *l_p_i = i_p - 1;
                                while(l_len && *l_p_i == ' ') { --l_len; --l_p_i; }
                                l_val_str.append(l_val, l_len);
                                //NDBG_PRINT("l_key: \"%s\"\n", l_key_str.c_str());
                                //NDBG_PRINT("l_val: \"%s\"\n", l_val_str.c_str());
                                kv_map_list_insert(ao_cookie_map, l_key_str, l_val_str);
                        }
                        else
                        {
                                // we got a key with no value
                                std::string l_key_str;
                                l_key_str.append(l_key, (int)(i_p - l_key));
                                std::string l_val_str;
                                kv_map_list_insert(ao_cookie_map, l_key_str, l_val_str);
                        }
                        // jump to next non-delimiter char
                        i_p++;
                        //NDBG_PRINT("SKIP l_del_chars\n");
                        for(; is_char_in_set(l_del_set, sizeof(l_del_set), *i_p); ++i_p) {}
                        if (*i_p == '\0') return WAFLZ_STATUS_OK;
                        l_key = i_p;
                        l_val = NULL;
                        l_keyend = NULL;
                }
                }
        }
        return WAFLZ_STATUS_OK;
}
}
