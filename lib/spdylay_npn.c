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
#include "spdylay_npn.h"

#include <string.h>

static const spdylay_npn_proto proto_list[] = {
  { (const unsigned char*)"spdy/3.1", 8, SPDYLAY_PROTO_SPDY3_1 },
  { (const unsigned char*)"spdy/3", 6, SPDYLAY_PROTO_SPDY3 },
  { (const unsigned char*)"spdy/2", 6, SPDYLAY_PROTO_SPDY2 }
};

const spdylay_npn_proto* spdylay_npn_get_proto_list(size_t *len_ptr)
{
  *len_ptr = sizeof(proto_list)/sizeof(spdylay_npn_proto);
  return proto_list;
}

int spdylay_select_next_protocol(unsigned char **out, unsigned char *outlen,
                                 const unsigned char *in, unsigned int inlen)
{
  const unsigned int SPDYLAY_SPDY_NOT_SELECTED = 99;
  int http_selected = 0;
  unsigned int selected_spdy_proto_pri = SPDYLAY_SPDY_NOT_SELECTED;
  unsigned int i = 0;
  for(; i < inlen; i += in[i]+1) {
    unsigned int j;
    for(j = 0; j < sizeof(proto_list)/sizeof(spdylay_npn_proto); ++j) {
      if(in[i] == proto_list[j].len &&
         i + 1 + in[i] <= inlen &&
         memcmp(&in[i+1], proto_list[j].proto, in[i]) == 0) {

        if(selected_spdy_proto_pri > j) {
          *out = (unsigned char*)&in[i+1];
          *outlen = in[i];
          selected_spdy_proto_pri = j;
        }
      }
    }
    if(selected_spdy_proto_pri == SPDYLAY_SPDY_NOT_SELECTED &&
       in[i] == 8 && i + 1 + in[i] <= inlen &&
       memcmp(&in[i+1], "http/1.1", in[i]) == 0) {
      http_selected = 1;
      *out = (unsigned char*)&in[i+1];
      *outlen = in[i];
      /* Go through to the next iteration, because "spdy/X" may be
         there */
    }
  }

  if(selected_spdy_proto_pri == SPDYLAY_SPDY_NOT_SELECTED) {
    if(http_selected) {
      return 0;
    }

    return -1;
  }

  return proto_list[selected_spdy_proto_pri].version;
}

uint16_t spdylay_npn_get_version(const unsigned char *proto, size_t protolen)
{
  if(proto == NULL) {
    return 0;
  } else {
    if(protolen == 8) {
      if(memcmp("spdy/3.1", proto, 8) == 0) {
        return SPDYLAY_PROTO_SPDY3_1;
      }
    } else if(protolen == 6) {
      if(memcmp("spdy/3", proto, 6) == 0) {
        return SPDYLAY_PROTO_SPDY3;
      } else if(memcmp("spdy/2", proto, 6) == 0) {
        return SPDYLAY_PROTO_SPDY2;
      }
    }
    return 0;
  }
}
