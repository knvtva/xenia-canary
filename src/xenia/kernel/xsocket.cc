/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2013 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include "src/xenia/kernel/xsocket.h"

#include <cstring>

#include "xenia/base/platform.h"
#include "xenia/kernel/kernel_state.h"
#include "xenia/kernel/xam/xam_module.h"
// #include "xenia/kernel/xnet.h"

#ifdef XE_PLATFORM_WIN32
// clang-format off
#include "xenia/base/platform_win.h"
#include <WS2tcpip.h>
#include <WinSock2.h>
// clang-format on
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace xe {
namespace kernel {


XSocket::XSocket(KernelState* kernel_state)
    : XObject(kernel_state, kObjectType) {}

XSocket::XSocket(KernelState* kernel_state, uint64_t native_handle)
    : XObject(kernel_state, kObjectType), native_handle_(native_handle) {}

XSocket::~XSocket() { Close(); }

X_STATUS XSocket::Initialize(AddressFamily af, Type type, Protocol proto) {
  af_ = af;
  type_ = type;
  proto_ = proto;

  if (proto == Protocol::X_IPPROTO_VDP) {
    // VDP is a layer on top of UDP.
    proto = Protocol::X_IPPROTO_UDP;
  }

  native_handle_ = socket(af, type, proto);
  if (native_handle_ == -1) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Close() {
#if XE_PLATFORM_WIN32
  int ret = closesocket(native_handle_);
#elif XE_PLATFORM_LINUX
  int ret = close(native_handle_);
#endif

  if (ret != 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::GetOption(uint32_t level, uint32_t optname, void* optval_ptr,
                            int* optlen) {
  int ret =
      getsockopt(native_handle_, level, optname, (char*)optval_ptr, optlen);
  if (ret < 0) {
    // TODO: WSAGetLastError()
    return X_STATUS_UNSUCCESSFUL;
  }
  return X_STATUS_SUCCESS;
}
X_STATUS XSocket::SetOption(uint32_t level, uint32_t optname, void* optval_ptr,
                            uint32_t optlen) {
  if (level == 0xFFFF && (optname == 0x5801 || optname == 0x5802)) {
    // Disable socket encryption
    secure_ = false;
    return X_STATUS_SUCCESS;
  }

  int ret =
      setsockopt(native_handle_, level, optname, (char*)optval_ptr, optlen);
  if (ret < 0) {
    // TODO: WSAGetLastError()
    return X_STATUS_UNSUCCESSFUL;
  }

  // SO_BROADCAST
  if (level == 0xFFFF && optname == 0x0020) {
    broadcast_socket_ = true;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::IOControl(uint32_t cmd, uint8_t* arg_ptr) {
#ifdef XE_PLATFORM_WIN32
  int ret = ioctlsocket(native_handle_, cmd, (u_long*)arg_ptr);
  if (ret < 0) {
    // TODO: Get last error
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
#elif XE_PLATFORM_LINUX
  return X_STATUS_UNSUCCESSFUL;
#endif
}

X_STATUS XSocket::Connect(const XSOCKADDR* name, int name_len) {
  sockaddr_storage n_name;
  auto family_size =
      offsetof(sockaddr_storage, ss_family) + sizeof(n_name.ss_family);
  if (name_len > sizeof(n_name) || name_len < family_size) {
    SetLastWSAError(X_WSAError::X_WSAEFAULT);
    return X_STATUS_UNSUCCESSFUL;
  }

  n_name.ss_family = name->address_family;
  std::memcpy(reinterpret_cast<uint8_t*>(&n_name) + family_size, name->sa_data,
              name_len - family_size);
  int ret = connect(native_handle_, (const sockaddr*)&n_name, name_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Bind(const XSOCKADDR* name, int name_len) {
  sockaddr_storage n_name;
  auto family_size =
      offsetof(sockaddr_storage, ss_family) + sizeof(n_name.ss_family);
  if (name_len > sizeof(n_name) || name_len < family_size) {
    SetLastWSAError(X_WSAError::X_WSAEFAULT);
    return X_STATUS_UNSUCCESSFUL;
  }

  n_name.ss_family = name->address_family;
  std::memcpy(reinterpret_cast<uint8_t*>(&n_name) + family_size, name->sa_data,
              name_len - family_size);
  int ret = bind(native_handle_, (const sockaddr*)&n_name, name_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  bound_ = true;
  bound_port_ = reinterpret_cast<sockaddr_in*>(&n_name)->sin_port;

  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::Listen(int backlog) {
  int ret = listen(native_handle_, backlog);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  return X_STATUS_SUCCESS;
}

object_ref<XSocket> XSocket::Accept(XSOCKADDR* name, int* name_len) {
  sockaddr_storage n_sockaddr;
  auto family_size =
      offsetof(sockaddr_storage, ss_family) + sizeof(n_sockaddr.ss_family);
  socklen_t n_name_len = 0;

  if (name_len) {
    n_name_len = *name_len;
    if (n_name_len > sizeof(n_sockaddr) || n_name_len < family_size) {
      SetLastWSAError(X_WSAError::X_WSAEFAULT);
      return nullptr;
    }
  }

  uintptr_t ret = accept(native_handle_,
                         name ? (sockaddr*)&n_sockaddr : nullptr, &n_name_len);
  if (ret == -1) {
    if (name && name_len) {
      std::memset(name, 0, *name_len);
      *name_len = 0;
    }
    return nullptr;
  }

  if (name) {
    name->address_family = n_sockaddr.ss_family;
    std::memcpy(name->sa_data,
                reinterpret_cast<uint8_t*>(&n_sockaddr) + family_size,
                n_name_len - family_size);
  }
  if (name_len) {
    *name_len = n_name_len;
  }

  // Create a kernel object to represent the new socket, and copy parameters
  // over.
  auto socket = object_ref<XSocket>(new XSocket(kernel_state_, ret));
  socket->af_ = af_;
  socket->type_ = type_;
  socket->proto_ = proto_;

  return socket;
}

int XSocket::Shutdown(int how) { return shutdown(native_handle_, how); }

int XSocket::Recv(uint8_t* buf, uint32_t buf_len, uint32_t flags) {
  return recv(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags);
}

int XSocket::RecvFrom(uint8_t* buf, uint32_t buf_len, uint32_t flags,
                      XSOCKADDR* from, uint32_t* from_len) {
  // Pop from secure packets first
  // TODO(DrChat): Enable when I commit XNet
  /*
  {
    std::lock_guard<std::mutex> lock(incoming_packet_mutex_);
    if (incoming_packets_.size()) {
      packet* pkt = (packet*)incoming_packets_.front();
      int data_len = pkt->data_len;
      std::memcpy(buf, pkt->data, std::min((uint32_t)pkt->data_len, buf_len));

      from->sin_family = 2;
      from->sin_addr = pkt->src_ip;
      from->sin_port = pkt->src_port;

      incoming_packets_.pop();
      uint8_t* pkt_ui8 = (uint8_t*)pkt;
      delete[] pkt_ui8;

      return data_len;
    }
  }
  */

  sockaddr_storage nfrom;
  auto family_size =
      offsetof(sockaddr_storage, ss_family) + sizeof(nfrom.ss_family);
  socklen_t nfromlen = 0;

  if (from_len) {
    nfromlen = *from_len;
    if (nfromlen > sizeof(nfrom) || nfromlen < family_size) {
      SetLastWSAError(X_WSAError::X_WSAEFAULT);
      return -1;
    }
  }

  int ret = recvfrom(native_handle_, reinterpret_cast<char*>(buf), buf_len,
                     flags, from ? (sockaddr*)&nfrom : nullptr, &nfromlen);

  if (from) {
    from->address_family = nfrom.ss_family;
    std::memcpy(from->sa_data, reinterpret_cast<uint8_t*>(&nfrom) + family_size,
                nfromlen - family_size);
  }
  if (from_len) {
    *from_len = nfromlen;
  }

  return ret;
}

int XSocket::Send(const uint8_t* buf, uint32_t buf_len, uint32_t flags) {
  return send(native_handle_, reinterpret_cast<const char*>(buf), buf_len,
              flags);
}

int XSocket::SendTo(uint8_t* buf, uint32_t buf_len, uint32_t flags,
                    XSOCKADDR* to, uint32_t to_len) {
  // Send 2 copies of the packet: One to XNet (for network security) and an
  // unencrypted copy for other Xenia hosts.
  // TODO(DrChat): Enable when I commit XNet.
  /*
  auto xam = kernel_state()->GetKernelModule<xam::XamModule>("xam.xex");
  auto xnet = xam->xnet();
  if (xnet) {
    xnet->SendPacket(this, to, buf, buf_len);
  }
  */

  sockaddr_storage nto;
  auto family_size =
      offsetof(sockaddr_storage, ss_family) + sizeof(nto.ss_family);
  if (to) {
    if (to_len > sizeof(nto) || to_len < family_size) {
      SetLastWSAError(X_WSAError::X_WSAEFAULT);
      return -1;
    }

    nto.ss_family = to->address_family;
    std::memcpy(reinterpret_cast<uint8_t*>(&nto) + family_size, to->sa_data,
                to_len - family_size);
  }

  return sendto(native_handle_, reinterpret_cast<char*>(buf), buf_len, flags,
                to ? (const sockaddr*)&nto : nullptr, to_len);
}

bool XSocket::QueuePacket(uint32_t src_ip, uint16_t src_port,
                          const uint8_t* buf, size_t len) {
  packet* pkt = reinterpret_cast<packet*>(new uint8_t[sizeof(packet) + len]);
  pkt->src_ip = src_ip;
  pkt->src_port = src_port;

  pkt->data_len = (uint16_t)len;
  std::memcpy(pkt->data, buf, len);

  std::lock_guard<std::mutex> lock(incoming_packet_mutex_);
  incoming_packets_.push((uint8_t*)pkt);

  // TODO: Limit on number of incoming packets?
  return true;
}

X_STATUS XSocket::GetPeerName(XSOCKADDR* buf, int* buf_len) {
  sockaddr_storage sa;
  auto family_size =
      offsetof(sockaddr_storage, ss_family) + sizeof(sa.ss_family);
  if (*buf_len > sizeof(sa) || *buf_len < family_size) {
    SetLastWSAError(X_WSAError::X_WSAEFAULT);
    return X_STATUS_UNSUCCESSFUL;
  }

  int ret = getpeername(native_handle_, (sockaddr*)&sa, (socklen_t*)buf_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  buf->address_family = sa.ss_family;
  std::memcpy(buf->sa_data, reinterpret_cast<uint8_t*>(&sa) + family_size,
              *buf_len - family_size);
  return X_STATUS_SUCCESS;
}

X_STATUS XSocket::GetSockName(XSOCKADDR* buf, int* buf_len) {
  sockaddr_storage sa;
  auto family_size =
      offsetof(sockaddr_storage, ss_family) + sizeof(sa.ss_family);
  if (*buf_len > sizeof(sa) || *buf_len < family_size) {
    SetLastWSAError(X_WSAError::X_WSAEFAULT);
    return X_STATUS_UNSUCCESSFUL;
  }

  int ret = getsockname(native_handle_, (sockaddr*)&sa, (socklen_t*)buf_len);
  if (ret < 0) {
    return X_STATUS_UNSUCCESSFUL;
  }

  buf->address_family = sa.ss_family;
  std::memcpy(buf->sa_data, reinterpret_cast<uint8_t*>(&sa) + family_size,
              *buf_len - family_size);
  return X_STATUS_SUCCESS;
}

uint32_t XSocket::GetLastWSAError() const {
  // Todo(Gliniak): Provide error mapping table
  // Xbox error codes might not match with what we receive from OS
#ifdef XE_PLATFORM_WIN32
  return WSAGetLastError();
#endif
  return errno;
}

void XSocket::SetLastWSAError(X_WSAError error) const {
#ifdef XE_PLATFORM_WIN32
  WSASetLastError((int)error);
#endif
  errno = (int)error;
}

}  // namespace kernel
}  // namespace xe