//: ----------------------------------------------------------------------------
//: Copyright (C) 2015 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: \file:    wafl_dump.cc
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
//: Includes
//: ----------------------------------------------------------------------------
#include "support/ndebug.h"
#include "waflz/waflz.h"
#include "waflz/wafl.h"
#include "waflz/wafl_filter.h"
#include "waflz/def.h"
#include <sys/time.h>
#include <sys/resource.h>
#include <list>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <termios.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>
#include <string.h>
//: ----------------------------------------------------------------------------
//: \details: Print the version.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void print_version(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "waflz_dump Parse and display Modsecurity Rule file/directory.\n");
        fprintf(a_stream, "Copyright (C) 2015 Verizon Digital Media.\n");
        fprintf(a_stream, "               Version: %d.%d.%d.%s\n",
                        WAFLZ_VERSION_MAJOR,
                        WAFLZ_VERSION_MINOR,
                        WAFLZ_VERSION_MACRO,
                        WAFLZ_VERSION_PATCH);
        exit(a_exit_code);
}
//: ----------------------------------------------------------------------------
//: \details: Print the command line help.
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
void print_usage(FILE* a_stream, int a_exit_code)
{
        fprintf(a_stream, "Usage: waflz_dump [options]\n");
        fprintf(a_stream, "Options are:\n");
        fprintf(a_stream, "  -h, --help           Display this help and exit.\n");
        fprintf(a_stream, "  -v, --version        Display the version number and exit.\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Input Options: (type defaults to Modsecurity)\n");
        fprintf(a_stream, "  -i, --input          File / Directory to read from (REQUIRED).\n");
        fprintf(a_stream, "  -M, --input_modsec   Input Type Modsecurity rules (file or directory)\n");
        fprintf(a_stream, "  -J, --input_json     Input Type Json\n");
        fprintf(a_stream, "  -P, --input_pbuf     Input Type Binary Protobuf (Default).\n");
        fprintf(a_stream, "  -l, --line           Single modsecurity rule line.\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Output Options: (type defaults to Json)\n");
        fprintf(a_stream, "  -o, --output         File to write to.\n");
        fprintf(a_stream, "  -j, --json           Output Type Json.\n");
        fprintf(a_stream, "  -p, --pbuf           Output Type Binary Protobuf.\n");
        fprintf(a_stream, "  -m, --modsec         Output Type ModSecurity format.\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Filter Options: \n");
        fprintf(a_stream, "  -f, --filter         Filter.\n");
        fprintf(a_stream, "  -F, --file_filter    Filter from file.\n");
        fprintf(a_stream, "  \n");
        fprintf(a_stream, "Print Options:\n");
        fprintf(a_stream, "  -r, --verbose        Verbose logging\n");
        fprintf(a_stream, "  -c, --color          Color\n");
        fprintf(a_stream, "  -s, --status         Status -show unhandled modsecurity info\n");
        fprintf(a_stream, "  \n");
        exit(a_exit_code);
}
//: ----------------------------------------------------------------------------
//: \details: TODO
//: \return:  TODO
//: \param:   TODO
//: ----------------------------------------------------------------------------
int main(int argc, char** argv)
{
        ns_waflz::wafl *l_wafl = new ns_waflz::wafl();
        // -------------------------------------------
        // Get args...
        // -------------------------------------------
        char l_opt;
        std::string l_argument;
        int l_option_index = 0;
        struct option l_long_options[] =
                {
                { "help",           0, 0, 'h' },
                { "version",        0, 0, 'v' },
                { "input",          1, 0, 'i' },
                { "input_modsec",   0, 0, 'M' },
                { "input_json",     0, 0, 'J' },
                { "input_pbuf",     0, 0, 'P' },
                { "output",         1, 0, 'o' },
                { "json",           0, 0, 'j' },
                { "pbuf",           0, 0, 'p' },
                { "modsec",         0, 0, 'm' },
                { "filter",         1, 0, 'f' },
                { "file_filter",    1, 0, 'F' },
                { "verbose",        0, 0, 'r' },
                { "color",          0, 0, 'c' },
                { "status",         0, 0, 's' },
                { "line",           1, 0, 'l' },
                // list sentinel
                { 0, 0, 0, 0 }
        };
        std::string l_input_file;
        std::string l_output_file;
        std::string l_file_filter;
        std::string l_filter_line;
        std::string l_input_line;
        ns_waflz::wafl_parser::format_t l_input_format = ns_waflz::wafl_parser::MODSECURITY;
        ns_waflz::wafl_parser::format_t l_output_format = ns_waflz::wafl_parser::JSON;
        bool l_show_status = false;
        // -------------------------------------------------
        // Args...
        // -------------------------------------------------
        char l_short_arg_list[] = "hvi:MJPo:jpmf:F:rcsl:";
        while((l_opt = getopt_long_only(argc, argv, l_short_arg_list, l_long_options, &l_option_index)) != -1)
        {
                if (optarg)
                {
                        l_argument = std::string(optarg);
                }
                else
                {
                        l_argument.clear();
                }
                //NDBG_PRINT("arg[%c=%d]: %s\n", l_opt, l_option_index, l_argument.c_str());
                switch (l_opt)
                {
                // ---------------------------------------
                // Help
                // ---------------------------------------
                case 'h':
                {
                        print_usage(stdout, 0);
                        break;
                }
                // ---------------------------------------
                // Version
                // ---------------------------------------
                case 'v':
                {
                        print_version(stdout, 0);
                        break;
                }
                // ---------------------------------------
                // input
                // ---------------------------------------
                case 'i':
                {
                        l_input_file = l_argument;
                        break;
                }
                // ---------------------------------------
                // modsecurity rules file/directory
                // ---------------------------------------
                case 'M':
                {
                        l_input_format = ns_waflz::wafl_parser::MODSECURITY;
                        break;
                }
                // ---------------------------------------
                // json
                // ---------------------------------------
                case 'J':
                {
                        l_input_format = ns_waflz::wafl_parser::JSON;
                        break;
                }
                // ---------------------------------------
                // pbuf
                // ---------------------------------------
                case 'P':
                {
                        l_input_format = ns_waflz::wafl_parser::PROTOBUF;
                        break;
                }
                // ---------------------------------------
                // output
                // ---------------------------------------
                case 'o':
                {
                        l_output_file = l_argument;
                        break;
                }
                // ---------------------------------------
                //
                // ---------------------------------------
                case 'j':
                {
                        l_output_format = ns_waflz::wafl_parser::JSON;
                        break;
                }

                // ---------------------------------------
                //
                // ---------------------------------------
                case 'p':
                {
                        l_output_format = ns_waflz::wafl_parser::PROTOBUF;
                        break;
                }
                // ---------------------------------------
                //
                // ---------------------------------------
                case 'm':
                {
                        l_output_format = ns_waflz::wafl_parser::MODSECURITY;
                        break;
                }
                // ---------------------------------------
                // filter
                // ---------------------------------------
                case 'f':
                {
                        l_filter_line = l_argument;
                        break;
                }
                // ---------------------------------------
                // filter file
                // ---------------------------------------
                case 'F':
                {
                        l_file_filter = l_argument;
                        break;
                }
                // ---------------------------------------
                // verbose
                // ---------------------------------------
                case 'r':
                {
                        l_wafl->set_verbose(true);
                        break;
                }
                // ---------------------------------------
                // color
                // ---------------------------------------
                case 'c':
                {
                        l_wafl->set_color(true);
                        break;
                }
                // ---------------------------------------
                // status
                // ---------------------------------------
                case 's':
                {
                        l_show_status = true;
                        break;
                }
                // ---------------------------------------
                // line
                // ---------------------------------------
                case 'l':
                {
                        l_input_line = l_argument;
                        break;
                }
                // ---------------------------------------
                // What???
                // ---------------------------------------
                case '?':
                {
                        // Required argument was missing
                        // '?' is provided when the 3rd arg to getopt_long does not begin with a ':', and is preceeded
                        // by an automatic error message.
                        fprintf(stdout, "  Exiting.\n");
                        print_usage(stdout, -1);
                        break;
                }

                // Huh???
                default:
                {
                        fprintf(stdout, "Unrecognized option.\n");
                        print_usage(stdout, -1);
                        break;
                }
                }
        }
        // -------------------------------------------
        // Read from input(s)
        // -------------------------------------------
        int32_t l_status;
        if(!l_input_line.empty())
        {
                l_status = l_wafl->init_line(l_input_format, l_input_line);
                if(l_status != WAFLZ_STATUS_OK)
                {
                        printf("Error: performing init_with_file: %s\n", l_input_file.c_str());
                        return WAFLZ_STATUS_ERROR;
                }
        }
        else
        {
                if(l_input_file.empty())
                {
                        fprintf(stdout, "Error input (file or directory) must be specified.\n");
                        print_usage(stdout, -1);
                }
                l_status = l_wafl->init(l_input_format, l_input_file);
                if(l_status != WAFLZ_STATUS_OK)
                {
                        printf("Error: performing init_with_file: %s\n", l_input_file.c_str());
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------
        // Get filter if any
        // -------------------------------------------
        ns_waflz::wafl_filter *l_filter = NULL;
        if(!l_file_filter.empty())
        {
                l_filter = new ns_waflz::wafl_filter();
                l_status = l_filter->init_with_file(l_file_filter);
                if(l_status != WAFLZ_STATUS_OK)
                {
                        printf("Error: performing init_with_file for filter file: %s\n", l_file_filter.c_str());
                        return WAFLZ_STATUS_ERROR;
                }

        }
        else if(!l_filter_line.empty())
        {
                l_filter = new ns_waflz::wafl_filter();
                l_status = l_filter->init_with_line(l_filter_line);
                if(l_status != WAFLZ_STATUS_OK)
                {
                        printf("Error: performing init_with_line for filter file: %s\n", l_filter_line.c_str());
                        return WAFLZ_STATUS_ERROR;
                }
        }
        if(l_filter)
        {
                l_wafl->filter(*l_filter);
        }
        //uint64_t l_start_time_ms = get_time_ms();
        //uint64_t l_end_time_ms = get_time_ms() - l_start_time_ms;
        // -------------------------------------------
        // Write out
        // -------------------------------------------
        // Get pbuf string
        std::string l_str;
        int32_t l_num_bytes_written = 0;
        l_status = l_wafl->get_str(l_str, l_output_format);
        if(l_status != WAFLZ_STATUS_OK)
        {
                printf("Error performing get_str.\n");
                return WAFLZ_STATUS_ERROR;
        }

        if(l_output_file.empty())
        {
                // Write
                l_num_bytes_written = fwrite(l_str.c_str(), 1, l_str.length(), stdout);
                if(l_num_bytes_written != (int32_t)l_str.length())
                {
                        printf("Error performing fwrite. Reason: %s\n", strerror(errno));
                        return WAFLZ_STATUS_ERROR;
                }
        }
        else
        {
                int32_t l_num_bytes_written = 0;
                // Open
                FILE *l_file_ptr = fopen(l_output_file.c_str(), "w+");
                if(l_file_ptr == NULL)
                {
                        printf("Error performing fopen. Reason: %s\n", strerror(errno));
                        return WAFLZ_STATUS_ERROR;
                }
                // Write
                l_num_bytes_written = fwrite(l_str.c_str(), 1, l_str.length(), l_file_ptr);
                if(l_num_bytes_written != (int32_t)l_str.length())
                {
                        printf("Error performing fwrite. Reason: %s\n", strerror(errno));
                        fclose(l_file_ptr);
                        return WAFLZ_STATUS_ERROR;
                }
                // Close
                l_status = fclose(l_file_ptr);
                if(l_status != 0)
                {
                        printf("Error performing fclose. Reason: %s\n", strerror(errno));
                        return WAFLZ_STATUS_ERROR;
                }
        }
        // -------------------------------------------
        // Status???
        // -------------------------------------------
        if(l_show_status)
        {
                // TODO
                l_wafl->show_status();
        }
        //l_wafl->show();
        // -------------------------------------------
        // Cleanup...
        // -------------------------------------------
        if(l_filter)
        {
                delete l_filter;
                l_filter = NULL;
        }
        if(l_wafl)
        {
                delete l_wafl;
                l_wafl = NULL;
        }
        return 0;
}
