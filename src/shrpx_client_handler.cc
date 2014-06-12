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
#include "shrpx_client_handler.h"

#include <unistd.h>
#include <cerrno>

#include "shrpx_upstream.h"
#include "shrpx_spdy_upstream.h"
#include "shrpx_https_upstream.h"
#include "shrpx_config.h"
#include "shrpx_http_downstream_connection.h"
#include "shrpx_spdy_downstream_connection.h"
#include "shrpx_accesslog.h"

namespace shrpx {

namespace {
void upstream_readcb(bufferevent *bev, void *arg)
{
  ClientHandler *handler = static_cast<ClientHandler*>(arg);
  int rv = handler->on_read();
  if(rv != 0) {
    delete handler;
  }
}
} // namespace

namespace {
void upstream_writecb(bufferevent *bev, void *arg)
{
  ClientHandler *handler = static_cast<ClientHandler*>(arg);
  // We actually depend on write low-watermark == 0.
  if(handler->get_outbuf_length() > 0) {
    // Possibly because of deferred callback, we may get this callback
    // when the output buffer is not empty.
    return;
  }
  if(handler->get_should_close_after_write()) {
    delete handler;
    return;
  }
  Upstream *upstream = handler->get_upstream();
  if(!upstream) {
    return;
  }
  int rv = upstream->on_write();
  if(rv != 0) {
    delete handler;
  }
}
} // namespace

namespace {
void upstream_eventcb(bufferevent *bev, short events, void *arg)
{
  ClientHandler *handler = static_cast<ClientHandler*>(arg);
  bool finish = false;
  if(events & BEV_EVENT_EOF) {
    if(LOG_ENABLED(INFO)) {
      CLOG(INFO, handler) << "EOF";
    }
    finish = true;
  }
  if(events & BEV_EVENT_ERROR) {
    if(LOG_ENABLED(INFO)) {
      CLOG(INFO, handler) << "Network error: "
                          << evutil_socket_error_to_string
        (EVUTIL_SOCKET_ERROR());
    }
    finish = true;
  }
  if(events & BEV_EVENT_TIMEOUT) {
    if(LOG_ENABLED(INFO)) {
      CLOG(INFO, handler) << "Time out";
    }
    finish = true;
  }
  if(finish) {
    delete handler;
  } else {
    if(events & BEV_EVENT_CONNECTED) {
      handler->set_tls_handshake(true);
      if(LOG_ENABLED(INFO)) {
        CLOG(INFO, handler) << "SSL/TLS handshake completed";
      }
      handler->set_bev_cb(upstream_readcb, upstream_writecb, upstream_eventcb);
      handler->validate_next_proto();
      if(LOG_ENABLED(INFO)) {
        if(SSL_session_reused(handler->get_ssl())) {
          CLOG(INFO, handler) << "SSL/TLS session reused";
        }
      }
      // At this point, input buffer is already filled with some
      // bytes.  The read callback is not called until new data
      // come. So consume input buffer here.
      handler->get_upstream()->on_read();
    }
  }
}
} // namespace

ClientHandler::ClientHandler(bufferevent *bev,
                             bufferevent_rate_limit_group *rate_limit_group,
                             int fd, SSL *ssl, const char *ipaddr)
  : ipaddr_(ipaddr),
    bev_(bev),
    ssl_(ssl),
    reneg_shutdown_timerev_(0),
    upstream_(0),
    spdy_(0),
    fd_(fd),
    should_close_after_write_(false),
    tls_handshake_(false),
    tls_renegotiation_(false)
{
  int rv;

  rv = bufferevent_set_rate_limit(bev_, get_config()->rate_limit_cfg);
  if(rv == -1) {
    CLOG(FATAL, this) << "bufferevent_set_rate_limit() failed";
  }

  rv = bufferevent_add_to_rate_limit_group(bev_, rate_limit_group);
  if(rv == -1) {
    CLOG(FATAL, this) << "bufferevent_add_to_rate_limit_group() failed";
  }

  bufferevent_enable(bev_, EV_READ | EV_WRITE);
  bufferevent_setwatermark(bev_, EV_READ, 0, SHRPX_READ_WATERMARK);
  set_upstream_timeouts(&get_config()->upstream_read_timeout,
                        &get_config()->upstream_write_timeout);
  if(ssl_) {
    SSL_set_app_data(ssl_, reinterpret_cast<char*>(this));
    set_bev_cb(0, upstream_writecb, upstream_eventcb);
  } else {
    if(get_config()->client_mode) {
      // Client mode
      upstream_ = new HttpsUpstream(this);
    } else {
      // no-TLS SPDY
      upstream_ = new SpdyUpstream(get_config()->spdy_upstream_version, this);
    }
    set_bev_cb(upstream_readcb, upstream_writecb, upstream_eventcb);
  }
}

ClientHandler::~ClientHandler()
{
  if(LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Deleting";
  }

  if(reneg_shutdown_timerev_) {
    event_free(reneg_shutdown_timerev_);
  }

  if(ssl_) {
    SSL_set_app_data(ssl_, 0);
    SSL_set_shutdown(ssl_, SSL_RECEIVED_SHUTDOWN);
    SSL_shutdown(ssl_);
  }

  bufferevent_remove_from_rate_limit_group(bev_);

  bufferevent_disable(bev_, EV_READ | EV_WRITE);
  bufferevent_free(bev_);

  if(ssl_) {
    SSL_free(ssl_);
  }
  shutdown(fd_, SHUT_WR);
  close(fd_);
  delete upstream_;
  for(std::set<DownstreamConnection*>::iterator i = dconn_pool_.begin();
      i != dconn_pool_.end(); ++i) {
    delete *i;
  }
  if(LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Deleted";
  }
}

Upstream* ClientHandler::get_upstream()
{
  return upstream_;
}

bufferevent* ClientHandler::get_bev() const
{
  return bev_;
}

event_base* ClientHandler::get_evbase() const
{
  return bufferevent_get_base(bev_);
}

void ClientHandler::set_bev_cb
(bufferevent_data_cb readcb, bufferevent_data_cb writecb,
 bufferevent_event_cb eventcb)
{
  bufferevent_setcb(bev_, readcb, writecb, eventcb, this);
}

void ClientHandler::set_upstream_timeouts(const timeval *read_timeout,
                                          const timeval *write_timeout)
{
  bufferevent_set_timeouts(bev_, read_timeout, write_timeout);
}

int ClientHandler::validate_next_proto()
{
  const unsigned char *next_proto = 0;
  unsigned int next_proto_len;
  SSL_get0_next_proto_negotiated(ssl_, &next_proto, &next_proto_len);
  if(next_proto) {
    if(LOG_ENABLED(INFO)) {
      std::string proto(next_proto, next_proto+next_proto_len);
      CLOG(INFO, this) << "The negotiated next protocol: " << proto;
    }
    uint16_t version = spdylay_npn_get_version(next_proto, next_proto_len);
    if(version) {
      SpdyUpstream *spdy_upstream = new SpdyUpstream(version, this);
      upstream_ = spdy_upstream;
      return 0;
    }
  } else {
    if(LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "No proto negotiated.";
    }
  }
  if(LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Use HTTP/1.1";
  }
  HttpsUpstream *https_upstream = new HttpsUpstream(this);
  upstream_ = https_upstream;
  return 0;
}

int ClientHandler::on_read()
{
  return upstream_->on_read();
}

int ClientHandler::on_event()
{
  return upstream_->on_event();
}

const std::string& ClientHandler::get_ipaddr() const
{
  return ipaddr_;
}

bool ClientHandler::get_should_close_after_write() const
{
  return should_close_after_write_;
}

void ClientHandler::set_should_close_after_write(bool f)
{
  should_close_after_write_ = f;
}

void ClientHandler::pool_downstream_connection(DownstreamConnection *dconn)
{
  if(LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Pooling downstream connection DCONN:" << dconn;
  }
  dconn_pool_.insert(dconn);
}

void ClientHandler::remove_downstream_connection(DownstreamConnection *dconn)
{
  if(LOG_ENABLED(INFO)) {
    CLOG(INFO, this) << "Removing downstream connection DCONN:" << dconn
                     << " from pool";
  }
  dconn_pool_.erase(dconn);
}

DownstreamConnection* ClientHandler::get_downstream_connection()
{
  if(dconn_pool_.empty()) {
    if(LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "Downstream connection pool is empty."
                       << " Create new one";
    }
    if(spdy_) {
      return new SpdyDownstreamConnection(this);
    } else {
      return new HttpDownstreamConnection(this);
    }
  } else {
    DownstreamConnection *dconn = *dconn_pool_.begin();
    dconn_pool_.erase(dconn);
    if(LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "Reuse downstream connection DCONN:" << dconn
                       << " from pool";
    }
    return dconn;
  }
}

size_t ClientHandler::get_outbuf_length()
{
  return evbuffer_get_length(bufferevent_get_output(bev_));
}

SSL* ClientHandler::get_ssl() const
{
  return ssl_;
}

void ClientHandler::set_spdy_session(SpdySession *spdy)
{
  spdy_ = spdy;
}

SpdySession* ClientHandler::get_spdy_session() const
{
  return spdy_;
}



void ClientHandler::set_tls_handshake(bool f)
{
  tls_handshake_ = f;
}

bool ClientHandler::get_tls_handshake() const
{
  return tls_handshake_;
}

namespace {
void shutdown_cb(evutil_socket_t fd, short what, void *arg)
{
  ClientHandler *handler = static_cast<ClientHandler*>(arg);

  if(LOG_ENABLED(INFO)) {
    CLOG(INFO, handler) << "Close connection due to TLS renegotiation";
  }

  delete handler;
}
} // namespace

void ClientHandler::set_tls_renegotiation(bool f)
{
  if(tls_renegotiation_ == false) {
    if(LOG_ENABLED(INFO)) {
      CLOG(INFO, this) << "TLS renegotiation detected. "
                       << "Start shutdown timer now.";
    }

    reneg_shutdown_timerev_ = evtimer_new(get_evbase(), shutdown_cb, this);
    event_priority_set(reneg_shutdown_timerev_, 0);

    timeval timeout = {0, 0};

    // TODO What to do if this failed?
    evtimer_add(reneg_shutdown_timerev_, &timeout);
  }

  tls_renegotiation_ = f;
}

bool ClientHandler::get_tls_renegotiation() const
{
  return tls_renegotiation_;
}

} // namespace shrpx
