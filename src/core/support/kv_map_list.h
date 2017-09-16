//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    kv_map_list.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    03/11/2015
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
#ifndef _KV_MAP_LIST_H
#define _KV_MAP_LIST_H
//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#include <string>
#include <list>
#include <map>
// for strcasecmp
#include <strings.h>
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: Types
//: ----------------------------------------------------------------------------
struct case_i_comp
{
        bool operator() (const std::string& lhs, const std::string& rhs) const
        {
                return strcasecmp(lhs.c_str(), rhs.c_str()) < 0;
        }
};
typedef std::list <std::string> str_list_t;
typedef std::map <std::string, str_list_t, case_i_comp> kv_map_list_t;
//: ----------------------------------------------------------------------------
//: insert
//: ----------------------------------------------------------------------------
inline void kv_map_list_insert(kv_map_list_t &ao_kv_map_list,
                               const std::string &a_key,
                               const std::string &a_val)
{
        kv_map_list_t::iterator i_obj = ao_kv_map_list.find(a_key);
        if(i_obj != ao_kv_map_list.end())
        {
                i_obj->second.push_back(a_val);
        }
        else
        {
                str_list_t l_list;
                l_list.push_back(a_val);
                ao_kv_map_list[a_key] = l_list;
        }
}

}
#endif
