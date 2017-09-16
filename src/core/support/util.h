//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    util.h
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
#ifndef _UTIL_H
#define _UTIL_H

//: ----------------------------------------------------------------------------
//: Includes
//: ----------------------------------------------------------------------------
#include <string>
#include <stdint.h>

//: ----------------------------------------------------------------------------
//: Fwd' Decls
//: ----------------------------------------------------------------------------

//: ----------------------------------------------------------------------------
//: Enums
//: ----------------------------------------------------------------------------


//: ----------------------------------------------------------------------------
//: Types
//: ----------------------------------------------------------------------------

//: ----------------------------------------------------------------------------
//: Prototypes
//: ----------------------------------------------------------------------------
int32_t break_header_string(const std::string &a_header_str, std::string &ao_header_key, std::string &ao_header_val);

// Time
uint64_t get_time_s(void);
uint64_t get_time_ms(void);
uint64_t get_time_us(void);
uint64_t get_delta_time_ms(uint64_t a_start_time_ms);
uint64_t get_delta_time_us(uint64_t a_start_time_us);

// file/path manipulation
std::string get_file_wo_path(const std::string &a_filename);
std::string get_file_path(const std::string &a_filename);
std::string get_base_filename(const std::string &a_filename);
std::string get_file_ext(const std::string &a_filename);
std::string get_file_wo_ext(const std::string &a_filename);

// uri
std::string uri_encode(const std::string & a_src);
std::string uri_decode(const std::string & a_src);


#endif





