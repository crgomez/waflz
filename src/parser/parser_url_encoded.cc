//: ----------------------------------------------------------------------------
//: Copyright (C) 2018 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    macro.cc
//: \details: TODO
//: \author:  Devender Singh
//: \date:    03/04/2018
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
#include "waflz/rqst_ctx.h"
#include "parser/parser_url_encoded.h"
#include "support/ndebug.h"
#include "core/decode.h"
namespace ns_waflz {
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
parser_url_encoded::parser_url_encoded(rqst_ctx *a_rqst_ctx):
        parser(a_rqst_ctx)
{
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
parser_url_encoded::~parser_url_encoded()
{
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t parser_url_encoded::init()
{
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t parser_url_encoded::process_chunk(const char *a_buf, uint32_t a_len)
{
        // TODO url encoded doesn't stream...
        return WAFLZ_STATUS_OK;
}
//: ----------------------------------------------------------------------------
//: \details TODO
//: \return  TODO
//: \param   TODO
//: ----------------------------------------------------------------------------
int32_t parser_url_encoded::finish(void)
{
        if(!m_rqst_ctx)
        {
                return WAFLZ_STATUS_ERROR;
        }
        if(!m_rqst_ctx->m_body_data ||
           !m_rqst_ctx->m_body_len)
        {
                return WAFLZ_STATUS_OK;
        }
        uint32_t l_invalid_cnt = 0;
        int32_t l_s;
        l_s = parse_args(m_rqst_ctx->m_body_arg_list,
                         l_invalid_cnt,
                         m_rqst_ctx->m_body_data,
                         m_rqst_ctx->m_body_len,
                         '&');
        if(l_s != WAFLZ_STATUS_OK)
        {
                return WAFLZ_STATUS_ERROR;
        }
        return WAFLZ_STATUS_OK;
}
}
