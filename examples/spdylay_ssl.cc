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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <cassert>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <string>
#include <set>
#include <iomanip>
#include <fstream>

#include "spdylay_ssl.h"

namespace spdylay {

bool ssl_debug = false;

Spdylay::Spdylay(int fd, SSL *ssl, uint16_t version,
                 const spdylay_session_callbacks *callbacks,
                 void *user_data)
  : fd_(fd), ssl_(ssl), version_(version), user_data_(user_data),
    want_write_(false)
{
  int r = spdylay_session_client_new(&session_, version_, callbacks, this);
  assert(r == 0);
}

Spdylay::~Spdylay()
{
  spdylay_session_del(session_);
}

int Spdylay::recv()
{
  return spdylay_session_recv(session_);
}

int Spdylay::send()
{
  return spdylay_session_send(session_);
}

ssize_t Spdylay::send_data(const uint8_t *data, size_t len, int flags)
{
  ssize_t r;
  ERR_clear_error();
  r = SSL_write(ssl_, data, len);
  return r;
}

ssize_t Spdylay::recv_data(uint8_t *data, size_t len, int flags)
{
  ssize_t r;
  want_write_ = false;
  ERR_clear_error();
  r = SSL_read(ssl_, data, len);
  if(r < 0) {
    if(SSL_get_error(ssl_, r) == SSL_ERROR_WANT_WRITE) {
      want_write_ = true;
    }
  }
  return r;
}

bool Spdylay::want_read()
{
  return spdylay_session_want_read(session_);
}

bool Spdylay::want_write()
{
  return spdylay_session_want_write(session_) || want_write_;
}

bool Spdylay::finish()
{
  return !spdylay_session_want_read(session_) &&
    !spdylay_session_want_write(session_);
}

int Spdylay::fd() const
{
  return fd_;
}

void* Spdylay::user_data()
{
  return user_data_;
}

int Spdylay::submit_request(const std::string& hostport,
                            const std::string& path, uint8_t pri,
                            void *stream_user_data)
{
  const char *nv[] = {
    ":method", "GET",
    ":path", path.c_str(),
    ":version", "HTTP/1.1",
    ":scheme", "https",
    ":host", hostport.c_str(),
    "accept", "*/*",
    "user-agent", "spdylay/"SPDYLAY_VERSION,
    NULL
  };
  return spdylay_submit_request(session_, pri, nv, NULL, stream_user_data);
}

int Spdylay::submit_settings(int flags, spdylay_settings_entry *iv, size_t niv)
{
  return spdylay_submit_settings(session_, flags, iv, niv);
}

bool Spdylay::would_block(int r)
{
  int e = SSL_get_error(ssl_, r);
  return e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ;
}

int connect_to(const std::string& host, uint16_t port)
{
  struct addrinfo hints;
  int fd = -1;
  int r;
  char service[10];
  snprintf(service, sizeof(service), "%u", port);
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo *res;
  r = getaddrinfo(host.c_str(), service, &hints, &res);
  if(r != 0) {
    std::cerr << "getaddrinfo: " << gai_strerror(r) << std::endl;
    return -1;
  }
  for(struct addrinfo *rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if(fd == -1) {
      continue;
    }
    while((r = connect(fd, rp->ai_addr, rp->ai_addrlen)) == -1 &&
          errno == EINTR);
    if(r == 0) {
      break;
    }
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

int make_listen_socket(const std::string& host, uint16_t port, int family)
{
  addrinfo hints;
  int fd = -1;
  int r;
  char service[10];
  snprintf(service, sizeof(service), "%u", port);
  memset(&hints, 0, sizeof(addrinfo));
  hints.ai_family = family;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif // AI_ADDRCONFIG
  addrinfo *res, *rp;
  const char* host_ptr;
  if(host.empty()) {
    host_ptr = 0;
  } else {
    host_ptr = host.c_str();
  }
  r = getaddrinfo(host_ptr, service, &hints, &res);
  if(r != 0) {
    std::cerr << "getaddrinfo: " << gai_strerror(r) << std::endl;
    return -1;
  }
  for(rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if(fd == -1) {
      continue;
    }
    int val = 1;
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val,
                  static_cast<socklen_t>(sizeof(val))) == -1) {
      close(fd);
      continue;
    }
#ifdef IPV6_V6ONLY
    if(family == AF_INET6) {
      if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val,
                    static_cast<socklen_t>(sizeof(val))) == -1) {
        close(fd);
        continue;
      }
    }
#endif // IPV6_V6ONLY

    if(bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
      break;
    }
    close(fd);
  }
  freeaddrinfo(res);
  if(rp == 0) {
    return -1;
  } else {
    if(listen(fd, 16) == -1) {
      close(fd);
      return -1;
    } else {
      return fd;
    }
  }
}

int make_non_block(int fd)
{
  int flags, r;
  while((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR);
  if(flags == -1) {
    return -1;
  }
  while((r = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR);
  if(r == -1) {
    return -1;
  }
  return 0;
}

int set_tcp_nodelay(int fd)
{
  int val = 1;
  return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val));
}

ssize_t send_callback(spdylay_session *session,
                      const uint8_t *data, size_t len, int flags,
                      void *user_data)
{
  Spdylay *sc = (Spdylay*)user_data;
  ssize_t r = sc->send_data(data, len, flags);
  if(r < 0) {
    if(sc->would_block(r)) {
      r = SPDYLAY_ERR_WOULDBLOCK;
    } else {
      r = SPDYLAY_ERR_CALLBACK_FAILURE;
    }
  }
  return r;
}

ssize_t recv_callback(spdylay_session *session,
                      uint8_t *data, size_t len, int flags, void *user_data)
{
  Spdylay *sc = (Spdylay*)user_data;
  ssize_t r = sc->recv_data(data, len, flags);
  if(r < 0) {
    if(sc->would_block(r)) {
      r = SPDYLAY_ERR_WOULDBLOCK;
    } else {
      r = SPDYLAY_ERR_CALLBACK_FAILURE;
    }
  } else if(r == 0) {
    r = SPDYLAY_ERR_EOF;
  }
  return r;
}

namespace {
const char *ctrl_names[] = {
  "SYN_STREAM",
  "SYN_REPLY",
  "RST_STREAM",
  "SETTINGS",
  "NOOP",
  "PING",
  "GOAWAY",
  "HEADERS",
  "WINDOW_UPDATE"
};
} // namespace

namespace {
void print_frame_attr_indent()
{
  printf("          ");
}
} // namespace

void print_nv(char **nv)
{
  int i;
  for(i = 0; nv[i]; i += 2) {
    print_frame_attr_indent();
    printf("%s: %s\n", nv[i], nv[i+1]);
  }
}

void print_timer()
{
  timeval tv;
  get_timer(&tv);
  printf("[%3ld.%03ld]", tv.tv_sec, tv.tv_usec/1000);
}

namespace {
void print_ctrl_hd(const spdylay_ctrl_hd& hd)
{
  printf("<version=%u, flags=%u, length=%d>\n",
         hd.version, hd.flags, hd.length);
}
} // namespace

namespace {
void print_frame(spdylay_frame_type type, spdylay_frame *frame)
{
  printf("%s frame ", ctrl_names[type-1]);
  print_ctrl_hd(frame->syn_stream.hd);
  switch(type) {
  case SPDYLAY_SYN_STREAM:
    print_frame_attr_indent();
    printf("(stream_id=%d, assoc_stream_id=%d, pri=%u)\n",
           frame->syn_stream.stream_id, frame->syn_stream.assoc_stream_id,
           frame->syn_stream.pri);
    print_nv(frame->syn_stream.nv);
    break;
  case SPDYLAY_SYN_REPLY:
    print_frame_attr_indent();
    printf("(stream_id=%d)\n", frame->syn_reply.stream_id);
    print_nv(frame->syn_reply.nv);
    break;
  case SPDYLAY_RST_STREAM:
    print_frame_attr_indent();
    printf("(stream_id=%d, status_code=%u)\n",
           frame->rst_stream.stream_id, frame->rst_stream.status_code);
    break;
  case SPDYLAY_SETTINGS:
    print_frame_attr_indent();
    printf("(niv=%lu)\n", static_cast<unsigned long>(frame->settings.niv));
    for(size_t i = 0; i < frame->settings.niv; ++i) {
      print_frame_attr_indent();
      printf("[%d(%u):%u]\n",
             frame->settings.iv[i].settings_id,
             frame->settings.iv[i].flags, frame->settings.iv[i].value);
    }
    break;
  case SPDYLAY_PING:
    print_frame_attr_indent();
    printf("(unique_id=%d)\n", frame->ping.unique_id);
    break;
  case SPDYLAY_GOAWAY:
    print_frame_attr_indent();
    printf("(last_good_stream_id=%d)\n", frame->goaway.last_good_stream_id);
    break;
  case SPDYLAY_HEADERS:
    print_frame_attr_indent();
    printf("(stream_id=%d)\n", frame->headers.stream_id);
    print_nv(frame->headers.nv);
    break;
  case SPDYLAY_WINDOW_UPDATE:
    print_frame_attr_indent();
    printf("(stream_id=%d, delta_window_size=%d)\n",
           frame->window_update.stream_id,
           frame->window_update.delta_window_size);
    break;
  default:
    printf("\n");
    break;
  }
}
} // namespace

void on_ctrl_recv_callback
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  print_timer();
  printf(" recv ");
  print_frame(type, frame);
  fflush(stdout);
}

namespace {
const char* strstatus(uint32_t status_code)
{
  switch(status_code) {
  case SPDYLAY_OK:
    return "OK";
  case SPDYLAY_PROTOCOL_ERROR:
    return "PROTOCOL_ERROR";
  case SPDYLAY_INVALID_STREAM:
    return "INVALID_STREAM";
  case SPDYLAY_REFUSED_STREAM:
    return "REFUSED_STREAM";
  case SPDYLAY_UNSUPPORTED_VERSION:
    return "UNSUPPORTED_VERSION";
  case SPDYLAY_CANCEL:
    return "CANCEL";
  case SPDYLAY_INTERNAL_ERROR:
    return "INTERNAL_ERROR";
  case SPDYLAY_FLOW_CONTROL_ERROR:
    return "FLOW_CONTROL_ERROR";
  case SPDYLAY_STREAM_IN_USE:
    return "STREAM_IN_USE";
  case SPDYLAY_STREAM_ALREADY_CLOSED:
    return "STREAM_ALREADY_CLOSED";
  case SPDYLAY_INVALID_CREDENTIALS:
    return "INVALID_CREDENTIALS";
  case SPDYLAY_FRAME_TOO_LARGE:
    return "FRAME_TOO_LARGE";
  default:
    return "Unknown status code";
  }
}
} // namespace

void on_invalid_ctrl_recv_callback
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 uint32_t status_code, void *user_data)
{
  print_timer();
  printf(" [INVALID; status=%s] recv ", strstatus(status_code));
  print_frame(type, frame);
  fflush(stdout);
}

namespace {
void dump_header(const uint8_t *head, size_t headlen)
{
  size_t i;
  print_frame_attr_indent();
  printf("Header dump: ");
  for(i = 0; i < headlen; ++i) {
    printf("%02X ", head[i]);
  }
  printf("\n");
}
} // namespace

void on_ctrl_recv_parse_error_callback(spdylay_session *session,
                                       spdylay_frame_type type,
                                       const uint8_t *head,
                                       size_t headlen,
                                       const uint8_t *payload,
                                       size_t payloadlen,
                                       int error_code, void *user_data)
{
  print_timer();
  printf(" [PARSE_ERROR] recv %s frame\n", ctrl_names[type-1]);
  print_frame_attr_indent();
  printf("Error: %s\n", spdylay_strerror(error_code));
  dump_header(head, headlen);
  fflush(stdout);
}

void on_unknown_ctrl_recv_callback(spdylay_session *session,
                                   const uint8_t *head,
                                   size_t headlen,
                                   const uint8_t *payload,
                                   size_t payloadlen,
                                   void *user_data)
{
  print_timer();
  printf(" recv unknown frame\n");
  dump_header(head, headlen);
  fflush(stdout);
}

void on_ctrl_send_callback
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  print_timer();
  printf(" send ");
  print_frame(type, frame);
  fflush(stdout);
}

namespace {
void print_data_frame(uint8_t flags, int32_t stream_id, int32_t length)
{
  printf("DATA frame (stream_id=%d, flags=%d, length=%d)\n",
         stream_id, flags, length);
}
} // namespace

void on_data_recv_callback
(spdylay_session *session, uint8_t flags, int32_t stream_id, int32_t length,
 void *user_data)
{
  print_timer();
  printf(" recv ");
  print_data_frame(flags, stream_id, length);
  fflush(stdout);
}

void on_data_send_callback
(spdylay_session *session, uint8_t flags, int32_t stream_id, int32_t length,
 void *user_data)
{
  print_timer();
  printf(" send ");
  print_data_frame(flags, stream_id, length);
  fflush(stdout);
}

void ctl_poll(pollfd *pollfd, Spdylay *sc)
{
  pollfd->events = 0;
  if(sc->want_read()) {
    pollfd->events |= POLLIN;
  }
  if(sc->want_write()) {
    pollfd->events |= POLLOUT;
  }
}

int select_next_proto_cb(SSL* ssl,
                         unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg)
{
  if(ssl_debug) {
    print_timer();
    std::cout << " NPN select next protocol: the remote server offers:"
              << std::endl;
  }
  for(unsigned int i = 0; i < inlen; i += in[i]+1) {
    if(ssl_debug) {
      std::cout << "          * ";
      std::cout.write(reinterpret_cast<const char*>(&in[i+1]), in[i]);
      std::cout << std::endl;
    }
  }
  std::string& next_proto = *(std::string*)arg;
  if(next_proto.empty()) {
    if(spdylay_select_next_protocol(out, outlen, in, inlen) <= 0) {
      std::cerr << "Server did not advertise spdy/2 or spdy/3 protocol."
                << std::endl;
      abort();
    } else {
      next_proto.assign(&(*out)[0], &(*out)[*outlen]);
    }
  } else {
    *out = (unsigned char*)(next_proto.c_str());
    *outlen = next_proto.size();
  }
  if(ssl_debug) {
    std::cout << "          NPN selected the protocol: "
              << std::string((const char*)*out, (size_t)*outlen) << std::endl;
  }
  return SSL_TLSEXT_ERR_OK;
}

void setup_ssl_ctx(SSL_CTX *ssl_ctx, void *next_proto_select_cb_arg)
{
  /* Disable SSLv2 and enable all workarounds for buggy servers */
  SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
  SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb,
                                   next_proto_select_cb_arg);
}

int ssl_handshake(SSL *ssl, int fd)
{
  if(SSL_set_fd(ssl, fd) == 0) {
    std::cerr << ERR_error_string(ERR_get_error(), 0) << std::endl;
    return -1;
  }
  ERR_clear_error();
  int r = SSL_connect(ssl);
  if(r <= 0) {
    std::cerr << ERR_error_string(ERR_get_error(), 0) << std::endl;
    return -1;
  }
  return 0;
}

namespace {
timeval base_tv;
} // namespace

void reset_timer()
{
  gettimeofday(&base_tv, 0);
}

void get_timer(timeval* tv)
{
  gettimeofday(tv, 0);
  tv->tv_usec -= base_tv.tv_usec;
  tv->tv_sec -= base_tv.tv_sec;
  if(tv->tv_usec < 0) {
    tv->tv_usec += 1000000;
    --tv->tv_sec;
  }
}

} // namespace spdylay
