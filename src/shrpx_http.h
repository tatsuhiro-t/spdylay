/*
 * Spdylay - SPDY Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef SHRPX_HTTP_H
#define SHRPX_HTTP_H

#include <string>

#include <spdylay/spdylay.h>

#include "http-parser/http_parser.h"

namespace shrpx {

namespace http {

std::string get_status_string(unsigned int status_code);

std::string create_error_html(unsigned int status_code);

std::string create_via_header_value(int major, int minor);

void capitalize(std::string& s, size_t offset);

// Returns false if |value| contains \r or \n.
bool check_header_value(const char *value);

void sanitize_header_value(std::string& s, size_t offset);

// Adds ANSI color codes to HTTP headers |hdrs|.
std::string colorizeHeaders(const char *hdrs);

// Copies the |field| component value from |u| and |url| to the
// |dest|. If |u| does not have |field|, then this function does
// nothing.
void copy_url_component(std::string& dest, http_parser_url *u, int field,
                        const char* url);

// Return positive window_size_increment if WINDOW_UPDATE should be
// sent for the stream |stream_id|. If |stream_id| == 0, this function
// determines the necessity of the WINDOW_UPDATE for a connection.
// The receiver window size is given in the |window_size|.
//
// If the function determines WINDOW_UPDATE is not necessary at the
// moment, it returns -1.
int32_t determine_window_update_transmission(spdylay_session *session,
                                             int32_t stream_id,
                                             int32_t window_size);

} // namespace http

} // namespace shrpx

#endif // SHRPX_HTTP_H
