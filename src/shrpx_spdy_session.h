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
#ifndef SHRPX_SPDY_SESSION_H
#define SHRPX_SPDY_SESSION_H

#include "shrpx.h"

#include <set>

#include <openssl/ssl.h>

#include <event.h>
#include <event2/bufferevent.h>

#include <spdylay/spdylay.h>

#include "http-parser/http_parser.h"

namespace shrpx {

class SpdyDownstreamConnection;

struct StreamData {
  SpdyDownstreamConnection *dconn;
};

class SpdySession {
public:
  SpdySession(event_base *evbase, SSL_CTX *ssl_ctx);
  ~SpdySession();

  int init_notification();

  int check_cert();

  int disconnect();
  int initiate_connection();

  void add_downstream_connection(SpdyDownstreamConnection *dconn);
  void remove_downstream_connection(SpdyDownstreamConnection *dconn);

  void remove_stream_data(StreamData *sd);

  int submit_request(SpdyDownstreamConnection *dconn,
                     uint8_t pri, const char **nv,
                     const spdylay_data_provider *data_prd);

  int submit_rst_stream(SpdyDownstreamConnection *dconn,
                        int32_t stream_id, uint32_t status_code);

  int submit_window_update(SpdyDownstreamConnection *dconn, int32_t amount);

  bool get_flow_control() const;

  int resume_data(SpdyDownstreamConnection *dconn);

  int on_connect();

  int on_read();
  int on_write();
  int send();

  int on_read_proxy();

  void clear_notify();
  void notify();

  bufferevent* get_bev() const;
  void unwrap_free_bev();

  int get_state() const;
  void set_state(int state);

  spdylay_session* get_session() const;

  size_t get_outbuf_length() const;

  enum {
    // Disconnected
    DISCONNECTED,
    // Connecting proxy and making CONNECT request
    PROXY_CONNECTING,
    // Tunnel is established with proxy
    PROXY_CONNECTED,
    // Establishing tunnel is failed
    PROXY_FAILED,
    // Connecting to downstream and/or performing SSL/TLS handshake
    CONNECTING,
    // Connected to downstream
    CONNECTED
  };

  static const size_t OUTBUF_MAX_THRES = 64*1024;
private:
  std::set<SpdyDownstreamConnection*> dconns_;
  std::set<StreamData*> streams_;
  event_base *evbase_;
  // NULL if no TLS is configured
  SSL_CTX *ssl_ctx_;
  SSL *ssl_;
  spdylay_session *session_;
  bufferevent *bev_;
  bufferevent *wrbev_;
  bufferevent *rdbev_;
  // Used to parse the response from HTTP proxy
  http_parser *proxy_htp_;
  // fd_ is used for proxy connection and no TLS connection. For
  // direct or TLS connection, it may be -1 even after connection is
  // established. Use bufferevent_getfd(bev_) to get file descriptor
  // in these cases.
  int fd_;
  int state_;
  bool notified_;
  bool flow_control_;
};

} // namespace shrpx

#endif // SHRPX_SPDY_SESSION_H
