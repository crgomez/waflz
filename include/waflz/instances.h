//: ----------------------------------------------------------------------------
//: Copyright (C) 2016 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    coordinators.h
//: \details: TODO
//: \author:  Reed P. Morrison
//: \date:    04/15/2016
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
#ifndef _INSTANCES_H_
#define _INSTANCES_H_
//: ----------------------------------------------------------------------------
//: includes
//: ----------------------------------------------------------------------------
#include "waflz/def.h"
#include "cityhash/city.h"
#include <string>
#include <vector>
#include <tr1/unordered_map>
namespace waflz_pb {
        class event;
}
namespace ns_waflz
{
//: ----------------------------------------------------------------------------
//: fwd decl's
//: ----------------------------------------------------------------------------
class instance;
class event;
class profile;
class geoip2_mmdb;
class engine;
//: ----------------------------------------------------------------------------
//: instances
//: ----------------------------------------------------------------------------
class instances
{
public:
        // -------------------------------------------------
        // Public types
        // -------------------------------------------------
        typedef std::vector <std::string> id_vector_t;
        // -------------------------------------------------
        // str hash
        // -------------------------------------------------
        struct str_hash
        {
                inline std::size_t operator()(const std::string& a_key) const
                {
                        return CityHash64(a_key.c_str(), a_key.length());
                }
        };
        typedef std::tr1::unordered_map<std::string, instance*, str_hash> id_instance_map_t;
        // -------------------------------------------------
        // Public methods
        // -------------------------------------------------
        instances(engine &a_engine,
                  bool a_enable_locking = false,
                  bool a_use_waflz = false);
        ~instances();
        int32_t init_dbs(void);
        int32_t load_config_file(instance **ao_instance,
                                 const char *a_file_path,
                                 uint32_t a_file_path_len,
                                 bool a_leave_compiled_file = false,
                                 bool a_update = false);
        int32_t load_config(instance **ao_instance,
                            const char *a_buf,
                            uint32_t a_buf_len,
                            bool a_leave_compiled_file = false,
                            bool a_update = false);
        int32_t load_config_dir(const char *a_dir_path,
                                uint32_t a_dir_path_len,
                                bool a_leave_compiled_file = false,
                                bool a_update = false);

        int32_t process_audit(waflz_pb::event **ao_event,
                              void *a_ctx,
                              const std::string &a_id);
        int32_t process_prod(waflz_pb::event **ao_event,
                             void *a_ctx,
                             const std::string &a_id);
        void set_locking(bool a_enable_locking) { m_enable_locking = a_enable_locking; }
        void set_use_waflz(bool a_use_waflz) { m_use_waflz = a_use_waflz; }
        const char *get_err_msg(void) { return m_err_msg; }
        instance *get_instance(const std::string &a_id);
        instance *get_first_instance(void);
        void get_instance_id_vector(id_vector_t &ao_id_vector);
private:
        // -------------------------------------------------
        // Private methods
        // -------------------------------------------------
        // Disallow copy/assign
        instances(const instances &);
        instances& operator=(const instances &);
        int32_t load_config(instance **ao_instance,
                            void *a_js,
                            bool a_leave_compiled_file = false,
                            bool a_update = false);
        // -------------------------------------------------
        // Private members
        // -------------------------------------------------
        bool m_init;
        char m_err_msg[WAFLZ_ERR_LEN];
        engine &m_engine;
        id_instance_map_t m_id_instance_map;
        pthread_mutex_t m_mutex;
        bool m_enable_locking;
        bool m_use_waflz;
        // -------------------------------------------------
        // *************************************************
        // geoip2 support
        // *************************************************
        // -------------------------------------------------
        geoip2_mmdb *m_geoip_mmdb;
};
}
#endif
