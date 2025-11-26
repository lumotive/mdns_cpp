#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <arpa/inet.h>

struct ServiceInfo {
  std::string instance_name;
  std::string host_name;
  std::string address;
  int port = 0;
  std::vector<std::pair<std::string, std::string>> txt_records;
  bool has_ptr = false, has_srv = false, has_a = false, has_txt = false;
};

#include "mdns_cpp/mdns.hpp"

#include <string.h>

#include <iostream>
#include <vector>
#include <memory>
#include <thread>

#include "mdns.h"
#include "mdns_cpp/logger.hpp"
#include "mdns_cpp/macros.hpp"

namespace mdns_cpp {

class ServiceDiscoveryContext {
public:
  std::map<std::string, ServiceInfo> services;
  std::mutex services_mutex;
};

static int discovery_query_callback(int sock, const struct sockaddr* from, size_t addrlen,
               mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype,
               uint16_t rclass, uint32_t ttl, const void* data, size_t size,
               size_t name_offset, size_t name_length, size_t record_offset,
               size_t record_length, void* user_data) {
  (void)sock;
  (void)from;
  (void)addrlen;
  (void)entry;
  (void)query_id;
  (void)rclass;
  (void)ttl;
  (void)name_length;
  ServiceDiscoveryContext* ctx = static_cast<ServiceDiscoveryContext*>(user_data);
  char name_buffer[256];
  mdns_string_t name = mdns_string_extract(data, size, &name_offset, name_buffer, sizeof(name_buffer));
  std::lock_guard<std::mutex> lock(ctx->services_mutex);
  if (rtype == MDNS_RECORDTYPE_PTR) {
    char ptr_buffer[256];
    mdns_string_t ptr = mdns_record_parse_ptr(data, size, record_offset, record_length, ptr_buffer, sizeof(ptr_buffer));
    std::string instance(ptr.str, ptr.length);
    ctx->services[instance].instance_name = instance;
    ctx->services[instance].has_ptr = true;
  } else if (rtype == MDNS_RECORDTYPE_SRV) {
    char srv_buffer[256];
    mdns_record_srv_t srv = mdns_record_parse_srv(data, size, record_offset, record_length, srv_buffer, sizeof(srv_buffer));
    std::string instance(name.str, name.length);
    std::string host(srv.name.str, srv.name.length);
    ctx->services[instance].host_name = host;
    ctx->services[instance].port = srv.port;
    ctx->services[instance].has_srv = true;
  } else if (rtype == MDNS_RECORDTYPE_A) {
    struct sockaddr_in addr;
    mdns_record_parse_a(data, size, record_offset, record_length, &addr);
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
    std::string hostname(name.str, name.length); // Use the actual hostname as key
    ctx->services[hostname].address = ip;
    ctx->services[hostname].host_name = hostname;
    ctx->services[hostname].has_a = true;
  } else if (rtype == MDNS_RECORDTYPE_TXT) {
    mdns_record_txt_t txt_records[8];
    size_t txt_count = mdns_record_parse_txt(data, size, record_offset, record_length, txt_records, 8);
    std::string instance(name.str, name.length);
    for (size_t i = 0; i < txt_count; ++i) {
      std::string key(txt_records[i].key.str, txt_records[i].key.length);
      std::string value(txt_records[i].value.str, txt_records[i].value.length);
      ctx->services[instance].txt_records.emplace_back(key, value);
    }
    ctx->services[instance].has_txt = true;
  }
  return 0;
}


static mdns_record_txt_t txtbuffer[128];

class ServiceRecord {
 public:
  std::string service;
  std::string hostname;
  std::string service_instance;
  std::string hostname_qualified;
  struct sockaddr_in address_ipv4;
  struct sockaddr_in6 address_ipv6;
  uint16_t port;
  mdns_record_t record_ptr;
  mdns_record_t record_srv;
  mdns_record_t record_a;
  mdns_record_t record_aaaa;
  std::vector<mdns_record_t> txt_records;
};

mdns_string_t to_mdns_str_ref(const std::string &str_ref) { return {str_ref.c_str(), str_ref.length()}; }

int mDNS::openServiceSockets(int *sockets, int max_sockets) {
  // When receiving, each socket can receive data from all network interfaces
  // Thus we only need to open one socket for each address family
  int num_sockets = 0;

  // Call the client socket function to enumerate and get local addresses,
  // but not open the actual sockets
  openClientSockets(0, 0, 0);

  if (num_sockets < max_sockets) {
    sockaddr_in sock_addr{};
    sock_addr.sin_family = AF_INET;
#ifdef _WIN32
    sock_addr.sin_addr = in4addr_any;
#else
    sock_addr.sin_addr.s_addr = INADDR_ANY;
#endif
    sock_addr.sin_port = htons(MDNS_PORT);
#ifdef __APPLE__
    sock_addr.sin_len = sizeof(struct sockaddr_in);
#endif
    const int sock = mdns_socket_open_ipv4(&sock_addr);
    if (sock >= 0) {
      sockets[num_sockets++] = sock;
    }
  }

  if (num_sockets < max_sockets) {
    sockaddr_in6 sock_addr{};
    sock_addr.sin6_family = AF_INET6;
    sock_addr.sin6_addr = in6addr_any;
    sock_addr.sin6_port = htons(MDNS_PORT);
#ifdef __APPLE__
    sock_addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
    int sock = mdns_socket_open_ipv6(&sock_addr);
    if (sock >= 0) sockets[num_sockets++] = sock;
  }

  return num_sockets;
}

// Callback handling questions and answers dump
static int dump_callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                         uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                         size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                         size_t record_length, void *user_data) {
  char addrbuffer[64]{};
  char namebuffer[256]{};

  const auto fromaddrstr = ipAddressToString(addrbuffer, sizeof(addrbuffer), from, addrlen);
  size_t offset = name_offset;
  mdns_string_t name = mdns_string_extract(data, size, &offset, namebuffer, sizeof(namebuffer));
  const char *record_name = 0;
  if (rtype == MDNS_RECORDTYPE_PTR)
    record_name = "PTR";
  else if (rtype == MDNS_RECORDTYPE_SRV)
    record_name = "SRV";
  else if (rtype == MDNS_RECORDTYPE_A)
    record_name = "A";
  else if (rtype == MDNS_RECORDTYPE_AAAA)
    record_name = "AAAA";
  else if (rtype == MDNS_RECORDTYPE_TXT)
    record_name = "TXT";
  else if (rtype == MDNS_RECORDTYPE_ANY)
    record_name = "ANY";
  else
    record_name = "<UNKNOWN>";
  const char *entry_type = "Question";
  if (entry == MDNS_ENTRYTYPE_ANSWER)
    entry_type = "Answer";
  else if (entry == MDNS_ENTRYTYPE_AUTHORITY)
    entry_type = "Authority";
  else if (entry == MDNS_ENTRYTYPE_ADDITIONAL)
    entry_type = "Additional";
  printf("%.*s: %s %s %.*s rclass 0x%x ttl %u\n", (int)fromaddrstr.length(), fromaddrstr.c_str(), entry_type,
         record_name, MDNS_STRING_FORMAT(name), (unsigned int)rclass, ttl);
  return 0;
}

int mDNS::openClientSockets(int *sockets, int max_sockets, int port) {
  // When sending, each socket can only send to one network interface
  // Thus we need to open one socket for each interface and address family
  int num_sockets = 0;

#ifdef _WIN32

  IP_ADAPTER_ADDRESSES *adapter_address = nullptr;
  ULONG address_size = 8000;
  unsigned int ret{};
  unsigned int num_retries = 4;
  do {
    adapter_address = (IP_ADAPTER_ADDRESSES *)malloc(address_size);
    ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, 0, adapter_address,
                               &address_size);
    if (ret == ERROR_BUFFER_OVERFLOW) {
      free(adapter_address);
      address_size *= 2;
    } else {
      break;
    }
  } while (num_retries-- > 0);

  if (!adapter_address || (ret != NO_ERROR)) {
    free(adapter_address);
    LogMessage() << "Failed to get network adapter addresses\n";
    return num_sockets;
  }

  int first_ipv4 = 1;
  int first_ipv6 = 1;
  for (PIP_ADAPTER_ADDRESSES adapter = adapter_address; adapter; adapter = adapter->Next) {
    if (adapter->TunnelType == TUNNEL_TYPE_TEREDO) {
      continue;
    }
    if (adapter->OperStatus != IfOperStatusUp) {
      continue;
    }

    for (IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
      if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
        struct sockaddr_in *saddr = (struct sockaddr_in *)unicast->Address.lpSockaddr;
        if ((saddr->sin_addr.S_un.S_un_b.s_b1 != 127) || (saddr->sin_addr.S_un.S_un_b.s_b2 != 0) ||
            (saddr->sin_addr.S_un.S_un_b.s_b3 != 0) || (saddr->sin_addr.S_un.S_un_b.s_b4 != 1)) {
          int log_addr = 0;
          if (first_ipv4) {
            service_address_ipv4_ = *saddr;
            first_ipv4 = 0;
            log_addr = 1;
          }

          if (num_sockets < max_sockets) {
            saddr->sin_port = htons((unsigned short)port);
            int sock = mdns_socket_open_ipv4(saddr);
            if (sock >= 0) {
              sockets[num_sockets++] = sock;
              log_addr = 1;
            } else {
              log_addr = 0;
            }
          }
          if (log_addr) {
            char buffer[128];
            const auto addr = ipv4AddressToString(buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in));
            MDNS_LOG << "Local IPv4 address: " << addr << "\n";
          }
        }
      } else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)unicast->Address.lpSockaddr;
        // Ignore link-local addresses
        if (saddr->sin6_scope_id) continue;
        static constexpr unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        static constexpr unsigned char localhost_mapped[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
        if ((unicast->DadState == NldsPreferred) && memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
            memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
          int log_addr = 0;
          if (first_ipv6) {
            memcpy(&service_address_ipv6_, &saddr->sin6_addr, sizeof(saddr->sin6_addr));
            first_ipv6 = 0;
            log_addr = 1;
          }

          if (num_sockets < max_sockets) {
            saddr->sin6_port = htons((unsigned short)port);
            int sock = mdns_socket_open_ipv6(saddr);
            if (sock >= 0) {
              sockets[num_sockets++] = sock;
              log_addr = 1;
            } else {
              log_addr = 0;
            }
          }
          if (log_addr) {
            char buffer[128];
            const auto addr = ipv6AddressToString(buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in6));
            MDNS_LOG << "Local IPv6 address: " << addr << "\n";
          }
        }
      }
    }
  }

  free(adapter_address);

#else

  struct ifaddrs *ifaddr = nullptr;
  struct ifaddrs *ifa = nullptr;

  if (getifaddrs(&ifaddr) < 0) {
    MDNS_LOG << "Unable to get interface addresses\n";
  }

  int first_ipv4 = 1;
  int first_ipv6 = 1;
  for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr) {
      continue;
    }
    if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_MULTICAST)) continue;
    if ((ifa->ifa_flags & IFF_LOOPBACK) || (ifa->ifa_flags & IFF_POINTOPOINT)) continue;

    if (ifa->ifa_addr->sa_family == AF_INET) {
      struct sockaddr_in *saddr = (struct sockaddr_in *)ifa->ifa_addr;
      if (saddr->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
        int log_addr = 0;
        if (first_ipv4) {
          service_address_ipv4_ = *saddr;
          first_ipv4 = 0;
          log_addr = 1;
        }

        if (num_sockets < max_sockets) {
          saddr->sin_port = htons(port);
          int sock = mdns_socket_open_ipv4(saddr);
          if (sock >= 0) {
            sockets[num_sockets++] = sock;
            log_addr = 1;
          } else {
            log_addr = 0;
          }
        }
        if (log_addr) {
          char buffer[128];
          const auto addr = ipv4AddressToString(buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in));
          MDNS_LOG << "Local IPv4 address: " << addr << "\n";
        }
      }
    } else if (ifa->ifa_addr->sa_family == AF_INET6) {
      struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)ifa->ifa_addr;
      // Ignore link-local addresses
      if (saddr->sin6_scope_id) continue;
      static constexpr unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
      static constexpr unsigned char localhost_mapped[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
      if (memcmp(saddr->sin6_addr.s6_addr, localhost, 16) && memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
        int log_addr = 0;
        if (first_ipv6) {
          service_address_ipv6_ = *saddr;
          first_ipv6 = 0;
          log_addr = 1;
        }

        if (num_sockets < max_sockets) {
          saddr->sin6_port = htons(port);
          int sock = mdns_socket_open_ipv6(saddr);
          if (sock >= 0) {
            sockets[num_sockets++] = sock;
            log_addr = 1;
          } else {
            log_addr = 0;
          }
        }
        if (log_addr) {
          char buffer[128] = {};
          const auto addr = ipv6AddressToString(buffer, sizeof(buffer), saddr, sizeof(struct sockaddr_in6));
          MDNS_LOG << "Local IPv6 address: " << addr << "\n";
        }
      }
    }
  }

  freeifaddrs(ifaddr);

#endif

  return num_sockets;
}

// Callback handling parsing answers to queries sent
static int query_callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                          uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                          size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                          size_t record_length, void *user_data) {
  (void)sizeof(sock);
  (void)sizeof(query_id);
  (void)sizeof(name_length);
  (void)sizeof(user_data);

  static char addrbuffer[64]{};
  static char namebuffer[256]{};
  static char entrybuffer[256]{};

  const auto fromaddrstr = ipAddressToString(addrbuffer, sizeof(addrbuffer), from, addrlen);
  const char *entrytype =
      (entry == MDNS_ENTRYTYPE_ANSWER) ? "answer" : ((entry == MDNS_ENTRYTYPE_AUTHORITY) ? "authority" : "additional");
  mdns_string_t entrystr = mdns_string_extract(data, size, &name_offset, entrybuffer, sizeof(entrybuffer));

  const int str_capacity = 1000;
  char str_buffer[str_capacity] = {};

  if (rtype == MDNS_RECORDTYPE_PTR) {
    mdns_string_t namestr =
        mdns_record_parse_ptr(data, size, record_offset, record_length, namebuffer, sizeof(namebuffer));

    snprintf(str_buffer, str_capacity, "%s : %s %.*s PTR %.*s rclass 0x%x ttl %u length %d\n", fromaddrstr.data(),
             entrytype, MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(namestr), rclass, ttl, (int)record_length);
  } else if (rtype == MDNS_RECORDTYPE_SRV) {
    mdns_record_srv_t srv =
        mdns_record_parse_srv(data, size, record_offset, record_length, namebuffer, sizeof(namebuffer));
    snprintf(str_buffer, str_capacity, "%s : %s %.*s SRV %.*s priority %d weight %d port %d\n", fromaddrstr.data(),
             entrytype, MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(srv.name), srv.priority, srv.weight, srv.port);
  } else if (rtype == MDNS_RECORDTYPE_A) {
    struct sockaddr_in addr;
    mdns_record_parse_a(data, size, record_offset, record_length, &addr);
    const auto addrstr = ipv4AddressToString(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
    snprintf(str_buffer, str_capacity, "%s : %s %.*s A %s\n", fromaddrstr.data(), entrytype,
             MDNS_STRING_FORMAT(entrystr), addrstr.data());
  } else if (rtype == MDNS_RECORDTYPE_AAAA) {
    struct sockaddr_in6 addr;
    mdns_record_parse_aaaa(data, size, record_offset, record_length, &addr);
    const auto addrstr = ipv6AddressToString(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
    snprintf(str_buffer, str_capacity, "%s : %s %.*s AAAA %s\n", fromaddrstr.data(), entrytype,
             MDNS_STRING_FORMAT(entrystr), addrstr.data());
  } else if (rtype == MDNS_RECORDTYPE_TXT) {
    size_t parsed = mdns_record_parse_txt(data, size, record_offset, record_length, txtbuffer,
                                          sizeof(txtbuffer) / sizeof(mdns_record_txt_t));
    for (size_t itxt = 0; itxt < parsed; ++itxt) {
      if (txtbuffer[itxt].value.length) {
        snprintf(str_buffer, str_capacity, "%s : %s %.*s TXT %.*s = %.*s\n", fromaddrstr.data(), entrytype,
                 MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(txtbuffer[itxt].key),
                 MDNS_STRING_FORMAT(txtbuffer[itxt].value));
      } else {
        snprintf(str_buffer, str_capacity, "%s : %s %.*s TXT %.*s\n", fromaddrstr.data(), entrytype,
                 MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(txtbuffer[itxt].key));
      }
    }
  } else {
    snprintf(str_buffer, str_capacity, "%s : %s %.*s type %u rclass 0x%x ttl %u length %d\n", fromaddrstr.data(),
             entrytype, MDNS_STRING_FORMAT(entrystr), rtype, rclass, ttl, (int)record_length);
  }
  MDNS_LOG << std::string(str_buffer);

  return 0;
}

// Callback handling questions incoming on service sockets
int service_callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type entry, uint16_t query_id,
                     uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data, size_t size, size_t name_offset,
                     size_t name_length, size_t record_offset, size_t record_length, void *user_data) {
  (void)sizeof(ttl);

  if (static_cast<int>(entry) != MDNS_ENTRYTYPE_QUESTION) {
    return 0;
  }

  const char dns_sd[] = "_services._dns-sd._udp.local.";
  const ServiceRecord *service_record = (const ServiceRecord *)user_data;

  char addrbuffer[64] = {0};
  char namebuffer[256] = {0};

  const auto fromaddrstr = ipAddressToString(addrbuffer, sizeof(addrbuffer), from, addrlen);
  const mdns_string_t service =
      mdns_record_parse_ptr(data, size, record_offset, record_length, namebuffer, sizeof(namebuffer));
  const size_t service_length = service_record->service.length();
  char sendbuffer[1024] = {0};

  size_t offset = name_offset;
  mdns_string_t name = mdns_string_extract(data, size, &offset, namebuffer, sizeof(namebuffer));

  const char *record_name = 0;
  if (rtype == MDNS_RECORDTYPE_PTR)
    record_name = "PTR";
  else if (rtype == MDNS_RECORDTYPE_SRV)
    record_name = "SRV";
  else if (rtype == MDNS_RECORDTYPE_A)
    record_name = "A";
  else if (rtype == MDNS_RECORDTYPE_AAAA)
    record_name = "AAAA";
  else if (rtype == MDNS_RECORDTYPE_TXT)
    record_name = "TXT";
  else if (rtype == MDNS_RECORDTYPE_ANY)
    record_name = "ANY";
  else
    return 0;
  MDNS_LOG << "Query " << record_name << MDNS_STRING_FORMAT(name);
  if ((name.length == (sizeof(dns_sd) - 1)) && (strncmp(name.str, dns_sd, sizeof(dns_sd) - 1) == 0)) {
    if ((rtype == MDNS_RECORDTYPE_PTR) || (rtype == MDNS_RECORDTYPE_ANY)) {
      // The PTR query was for the DNS-SD domain, send answer with a PTR record for the
      // service name we advertise, typically on the "<_service-name>._tcp.local." format
      // Answer PTR record reverse mapping "<_service-name>._tcp.local." to
      // "<hostname>.<_service-name>._tcp.local."
      mdns_record_t answer = {.name = name,
                              .type = MDNS_RECORDTYPE_PTR,
                              .data = {mdns_record_ptr_t{name = to_mdns_str_ref(service_record->service)}}};
      // Send the answer, unicast or multicast depending on flag in query
      uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
      printf("  --> answer %.*s (%s)\n", MDNS_STRING_FORMAT(answer.data.ptr.name), (unicast ? "unicast" : "multicast"));
      if (unicast) {
        mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id,
                                  static_cast<mdns_record_type_t>(rtype), name.str, name.length, answer, 0, 0, 0, 0);
      } else {
        mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, 0, 0);
      }
    }
  } else if ((service.length == service_length) &&
             (strncmp(service.str, service_record->service.c_str(), service_length) == 0)) {
    if ((rtype == MDNS_RECORDTYPE_PTR) || (rtype == MDNS_RECORDTYPE_ANY)) {
      // The PTR query was for our service (usually "<_service-name._tcp.local"), answer a PTR
      // record reverse mapping the queried service name to our service instance name
      // (typically on the "<hostname>.<_service-name>._tcp.local." format), and add
      // additional records containing the SRV record mapping the service instance name to our
      // qualified hostname (typically "<hostname>.local.") and port, as well as any IPv4/IPv6
      // address for the hostname as A/AAAA records, and two test TXT records
      // Answer PTR record reverse mapping "<_service-name>._tcp.local." to
      // "<hostname>.<_service-name>._tcp.local."
      mdns_record_t answer = service_record->record_ptr;
      mdns_record_t additional[5] = {{}};
      size_t additional_count = 0;
      // SRV record mapping "<hostname>.<_service-name>._tcp.local." to
      // "<hostname>.local." with port. Set weight & priority to 0.
      additional[additional_count++] = service_record->record_srv;
      // A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
      if (service_record->address_ipv4.sin_family == AF_INET) additional[additional_count++] = service_record->record_a;
      if (service_record->address_ipv6.sin6_family == AF_INET6)
        additional[additional_count++] = service_record->record_aaaa;
      // Add all TXT records for our service instance name
      for (const auto& txt_record : service_record->txt_records) {
        additional[additional_count++] = txt_record;
      }
      // Send the answer, unicast or multicast depending on flag in query
      uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
      printf("  --> answer %.*s port %d (%s)\n", MDNS_STRING_FORMAT(service_record->record_srv.data.srv.name),
             service_record->port, (unicast ? "unicast" : "multicast"));
      if (unicast) {
        mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id,
                                  static_cast<mdns_record_type_t>(rtype), name.str, name.length, answer, 0, 0,
                                  additional, additional_count);
      } else {
        mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, additional, additional_count);
      }
    }
  } else if ((name.length == service_record->service_instance.length()) &&
             (strncmp(name.str, service_record->service_instance.c_str(), name.length) == 0)) {
    if ((rtype == MDNS_RECORDTYPE_SRV) || (rtype == MDNS_RECORDTYPE_ANY)) {
      // The SRV query was for our service instance (usually
      // "<hostname>.<_service-name._tcp.local"), answer a SRV record mapping the service
      // instance name to our qualified hostname (typically "<hostname>.local.") and port, as
      // well as any IPv4/IPv6 address for the hostname as A/AAAA records, and two test TXT
      // records
      // Answer PTR record reverse mapping "<_service-name>._tcp.local." to
      // "<hostname>.<_service-name>._tcp.local."
      mdns_record_t answer = service_record->record_srv;
      mdns_record_t additional[5] = {{}};
      size_t additional_count = 0;
      // A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
      if (service_record->address_ipv4.sin_family == AF_INET) additional[additional_count++] = service_record->record_a;
      if (service_record->address_ipv6.sin6_family == AF_INET6)
        additional[additional_count++] = service_record->record_aaaa;
      // Add all TXT records for our service instance name
      for (const auto& txt_record : service_record->txt_records) {
        additional[additional_count++] = txt_record;
      }
      // Send the answer, unicast or multicast depending on flag in query
      uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
      printf("  --> answer %.*s port %d (%s)\n", MDNS_STRING_FORMAT(service_record->record_srv.data.srv.name),
             service_record->port, (unicast ? "unicast" : "multicast"));
      if (unicast) {
        mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id,
                                  static_cast<mdns_record_type_t>(rtype), name.str, name.length, answer, 0, 0,
                                  additional, additional_count);
      } else {
        mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, additional, additional_count);
      }
    }
  } else if ((name.length == service_record->hostname_qualified.length()) &&
             (strncmp(name.str, service_record->hostname_qualified.c_str(), name.length) == 0)) {
    if (((rtype == MDNS_RECORDTYPE_A) || (rtype == MDNS_RECORDTYPE_ANY)) &&
        (service_record->address_ipv4.sin_family == AF_INET)) {
      // The A query was for our qualified hostname (typically "<hostname>.local.") and we
      // have an IPv4 address, answer with an A record mappiing the hostname to an IPv4
      // address, as well as any IPv6 address for the hostname, and two test TXT records
      // Answer A records mapping "<hostname>.local." to IPv4 address
      mdns_record_t answer = service_record->record_a;
      mdns_record_t additional[5] = {{}};
      size_t additional_count = 0;
      // AAAA record mapping "<hostname>.local." to IPv6 addresses
      if (service_record->address_ipv6.sin6_family == AF_INET6)
        additional[additional_count++] = service_record->record_aaaa;
      // Add all TXT records for our service instance name
      for (const auto& txt_record : service_record->txt_records) {
        additional[additional_count++] = txt_record;
      }
      // Send the answer, unicast or multicast depending on flag in query
      uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
      const auto addrstr =
          ipAddressToString(addrbuffer, sizeof(addrbuffer), (struct sockaddr *)&service_record->record_a.data.a.addr,
                            sizeof(service_record->record_a.data.a.addr));
      printf("  --> answer %.*s IPv4 %.*s (%s)\n", MDNS_STRING_FORMAT(service_record->record_a.name),
             (int)addrstr.length(), addrstr.c_str(), (unicast ? "unicast" : "multicast"));
      if (unicast) {
        mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id,
                                  static_cast<mdns_record_type_t>(rtype), name.str, name.length, answer, 0, 0,
                                  additional, additional_count);
      } else {
        mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, additional, additional_count);
      }
    } else if (((rtype == MDNS_RECORDTYPE_AAAA) || (rtype == MDNS_RECORDTYPE_ANY)) &&
               (service_record->address_ipv6.sin6_family == AF_INET6)) {
      // The AAAA query was for our qualified hostname (typically "<hostname>.local.") and we
      // have an IPv6 address, answer with an AAAA record mappiing the hostname to an IPv6
      // address, as well as any IPv4 address for the hostname, and two test TXT records
      // Answer AAAA records mapping "<hostname>.local." to IPv6 address
      mdns_record_t answer = service_record->record_aaaa;
      mdns_record_t additional[5] = {{}};
      size_t additional_count = 0;
      // A record mapping "<hostname>.local." to IPv4 addresses
      if (service_record->address_ipv4.sin_family == AF_INET) additional[additional_count++] = service_record->record_a;
      // Add all TXT records for our service instance name
      for (const auto& txt_record : service_record->txt_records) {
        additional[additional_count++] = txt_record;
      }
      // Send the answer, unicast or multicast depending on flag in query
      uint16_t unicast = (rclass & MDNS_UNICAST_RESPONSE);
      auto addrstr = ipAddressToString(addrbuffer, sizeof(addrbuffer),
                                       (struct sockaddr *)&service_record->record_aaaa.data.aaaa.addr,
                                       sizeof(service_record->record_aaaa.data.aaaa.addr));
      printf("  --> answer %.*s IPv6 %.*s (%s)\n", MDNS_STRING_FORMAT(service_record->record_a.name),
             (int)addrstr.length(), addrstr.c_str(), (unicast ? "unicast" : "multicast"));
      if (unicast) {
        mdns_query_answer_unicast(sock, from, addrlen, sendbuffer, sizeof(sendbuffer), query_id,
                                  static_cast<mdns_record_type_t>(rtype), name.str, name.length, answer, 0, 0,
                                  additional, additional_count);
      } else {
        mdns_query_answer_multicast(sock, sendbuffer, sizeof(sendbuffer), answer, 0, 0, additional, additional_count);
      }
    }
    // #endif
  }
  return 0;
}

mDNS::~mDNS() { stopService(); }

void mDNS::startService(const bool dumpMode) {
  dumpMode_ = dumpMode;
  if (running_) {
    stopService();
  }

  running_ = true;
  worker_thread_ = std::thread([this]() { this->runMainLoop(); });
}

void mDNS::stopService() {
  running_ = false;
  if (worker_thread_.joinable()) {
    worker_thread_.join();
  }
}

bool mDNS::isServiceRunning() { return running_; }

void mDNS::setServiceHostname(const std::string &hostname) { hostname_ = hostname; }

void mDNS::setServicePort(std::uint16_t port) { port_ = port; }

void mDNS::setServiceName(const std::string &name) { name_ = name; }

void mDNS::setServiceTxtRecord(const std::string &txt_record) { txt_record_ = txt_record; }

void mDNS::runMainLoop() {
  constexpr size_t number_of_sockets = 32;
  int sockets[number_of_sockets];
  const int num_sockets = openServiceSockets(sockets, sizeof(sockets) / sizeof(sockets[0]));
  if (num_sockets <= 0) {
    const auto msg = "Error: Failed to open any client sockets";
    MDNS_LOG << msg << "\n";
    throw std::runtime_error(msg);
  }

  if (dumpMode_) {
    runDumpMode(sockets, num_sockets);
    dumpMode_ = false;
    return;
  }

  if (name_.length() == 0) {
    const auto msg = "Error: nvalid service name\n";
    MDNS_LOG << msg << "\n";
    throw std::runtime_error(msg);
  }
  if (!name_.ends_with(".")) name_ += ".";

  MDNS_LOG << "Opened " << std::to_string(num_sockets) << " socket" << (num_sockets > 1 ? "s" : "")
           << " for mDNS service\n";
  MDNS_LOG << "Service mDNS: " << name_ << ":" << port_ << "\n";
  MDNS_LOG << "Hostname: " << hostname_.data() << "\n";

  constexpr size_t capacity = 2048u;
  std::shared_ptr<void> buffer(malloc(capacity), free);
  ServiceRecord service_record{};
  service_record.service = name_;
  service_record.hostname = hostname_;
  {
    // Build the service instance "<hostname>.<_service-name>._tcp.local." string
    std::ostringstream oss;
    oss << hostname_ << "." << name_;
    service_record.service_instance = oss.str();
  }
  {
    // Build the "<hostname>.local." string
    std::ostringstream oss;
    oss << hostname_ << ".local.";
    service_record.hostname_qualified = oss.str();
  }
  service_record.address_ipv4 = service_address_ipv4_;
  service_record.address_ipv6 = service_address_ipv6_;
  service_record.port = port_;

  // Setup our mDNS records

  // PTR record reverse mapping "<_service-name>._tcp.local." to
  // "<hostname>.<_service-name>._tcp.local."
  service_record.record_ptr.name = to_mdns_str_ref(service_record.service);
  service_record.record_ptr.type = MDNS_RECORDTYPE_PTR,
  service_record.record_ptr.data.ptr = mdns_record_ptr_t{.name = to_mdns_str_ref(service_record.service_instance)};
  service_record.record_ptr.rclass = 0;
  service_record.record_ptr.ttl = 0;

  // SRV record mapping "<hostname>.<_service-name>._tcp.local." to
  // "<hostname>.local." with port. Set weight & priority to 0.
  service_record.record_srv.name = to_mdns_str_ref(service_record.service_instance);
  service_record.record_srv.type = MDNS_RECORDTYPE_SRV;
  service_record.record_srv.data.srv = mdns_record_srv_t{.priority = 0,
                                                         .weight = 0,
                                                         .port = service_record.port,
                                                         .name = to_mdns_str_ref(service_record.hostname_qualified)};
  service_record.record_srv.rclass = 0;
  service_record.record_srv.ttl = 0;

  // A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
  service_record.record_a.name = to_mdns_str_ref(service_record.hostname_qualified);
  service_record.record_a.type = MDNS_RECORDTYPE_A;
  service_record.record_a.data.a = {mdns_record_a_t{.addr = service_record.address_ipv4}};
  service_record.record_a.rclass = 0;
  service_record.record_a.ttl = 0;

  service_record.record_aaaa.name = to_mdns_str_ref(service_record.hostname_qualified);
  service_record.record_aaaa.type = MDNS_RECORDTYPE_AAAA,
  service_record.record_aaaa.data.aaaa.addr = service_record.address_ipv6;
  service_record.record_aaaa.rclass = 0;
  service_record.record_aaaa.ttl = 0;


  // Parse txt_record_ string and set up N TXT records
  // Format: "key1=value1;key2=value2" or "key1=value1,key2=value2"
  std::vector<std::pair<std::string, std::string>> txt_pairs;
  size_t start = 0;
  while (start < txt_record_.size()) {
    size_t end = txt_record_.find_first_of(";,", start);
    std::string pair = txt_record_.substr(start, end - start);
    size_t eq = pair.find('=');
    if (eq != std::string::npos) {
      txt_pairs.emplace_back(pair.substr(0, eq), pair.substr(eq + 1));
    } else if (!pair.empty()) {
      txt_pairs.emplace_back(pair, "");
    }
    if (end == std::string::npos) break;
    start = end + 1;
  }
  service_record.txt_records.clear();
  for (size_t i = 0; i < txt_pairs.size(); ++i) {
    mdns_record_t txt_record{};
    txt_record.name = to_mdns_str_ref(service_record.service_instance);
    txt_record.type = MDNS_RECORDTYPE_TXT;
    txt_record.data.txt = mdns_record_txt_t{
      .key = to_mdns_str_ref(txt_pairs[i].first),
      .value = to_mdns_str_ref(txt_pairs[i].second)
    };
    txt_record.rclass = 0;
    txt_record.ttl = 0;
    service_record.txt_records.push_back(txt_record);
  }

  // Send an announcement on startup of service
  {
    MDNS_LOG << "Sending announce\n";
    mdns_record_t additional[32] = {{}};
    size_t additional_count = 0;
    additional[additional_count++] = service_record.record_srv;
    if (service_record.address_ipv4.sin_family == AF_INET) additional[additional_count++] = service_record.record_a;
    if (service_record.address_ipv6.sin6_family == AF_INET6)
      additional[additional_count++] = service_record.record_aaaa;
    for (const auto& txt_record : service_record.txt_records) {
      additional[additional_count++] = txt_record;
    }
    for (int isock = 0; isock < num_sockets; ++isock)
      mdns_announce_multicast(sockets[isock], buffer.get(), capacity, service_record.record_ptr, 0, 0, additional,
                              additional_count);
  }

  // This is a crude implementation that checks for incoming queries
  while (running_) {
    int nfds = 0;
    fd_set readfs{};
    FD_ZERO(&readfs);
    for (int isock = 0; isock < num_sockets; ++isock) {
      if (sockets[isock] >= nfds) nfds = sockets[isock] + 1;
      FD_SET(sockets[isock], &readfs);
    }

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
    if (select(nfds, &readfs, 0, 0, &timeout) >= 0) {
      for (int isock = 0; isock < num_sockets; ++isock) {
        if (FD_ISSET(sockets[isock], &readfs)) {
          mdns_socket_listen(sockets[isock], buffer.get(), capacity, service_callback, &service_record);
        }
        FD_SET(sockets[isock], &readfs);
      }
    } else {
      break;
    }
  }

  // Send a goodbye on end of service
  {
    MDNS_LOG << "Sending goodbye\n";
    mdns_record_t additional[32] = {{}};
    size_t additional_count = 0;
    additional[additional_count++] = service_record.record_srv;
    if (service_record.address_ipv4.sin_family == AF_INET) additional[additional_count++] = service_record.record_a;
    if (service_record.address_ipv6.sin6_family == AF_INET6)
      additional[additional_count++] = service_record.record_aaaa;
    for (const auto& txt_record : service_record.txt_records) {
      additional[additional_count++] = txt_record;
    }

    for (int isock = 0; isock < num_sockets; ++isock)
      mdns_goodbye_multicast(sockets[isock], buffer.get(), capacity, service_record.record_ptr, 0, 0, additional,
                             additional_count);
  }

  for (int isock = 0; isock < num_sockets; ++isock) {
    mdns_socket_close(sockets[isock]);
  }
  MDNS_LOG << "Closed socket " << (num_sockets > 1 ? "s" : "") << "\n";
}

std::map<std::string, ServiceInfo> mDNS::executeQuery(ServiceQueries serviceQueries) {
  ServiceDiscoveryContext ctx;
  int sockets[32];
  int query_id[32];
  int num_sockets = openClientSockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0);
  if (num_sockets <= 0) {
    MDNS_LOG << "Failed to open any client sockets\n";
    return {};
  }
  size_t capacity = 2048;
  void *buffer = malloc(capacity);
  std::vector<mdns_query_t> queries;
  for (auto &query : serviceQueries) {
    auto &[name, type] = query;
    queries.push_back(mdns_query_t{static_cast<mdns_record_type>(type), name.c_str(), name.length()});
  }
  for (int isock = 0; isock < num_sockets; ++isock) {
    query_id[isock] = mdns_multiquery_send(sockets[isock], queries.data(), queries.size(), buffer, capacity, 0);
  }
  auto start = std::chrono::steady_clock::now();
  bool running = true;
  while (running) {
    for (int isock = 0; isock < num_sockets; ++isock) {
      mdns_query_recv(sockets[isock], buffer, capacity, discovery_query_callback, &ctx, query_id[isock]);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    if (elapsed > 5000) { // 5 seconds
      running = false;
    }
  }
  free(buffer);
  for (int isock = 0; isock < num_sockets; ++isock) {
    mdns_socket_close(sockets[isock]);
  }
  // Build a hostname->IP map from all A records
  std::map<std::string, std::string> hostname_to_ip;
  for (const auto& [key, info] : ctx.services) {
    if (!info.host_name.empty() && !info.address.empty() && info.has_a) {
      hostname_to_ip[info.host_name] = info.address;
    }
  }
  std::map<std::string, ServiceInfo> result;
  for (const auto& [key, info] : ctx.services) {
    if (info.has_ptr && info.has_srv && info.has_txt) {
      ServiceInfo complete = info;
      if (!info.host_name.empty()) {
        if (hostname_to_ip.count(info.host_name)) {
          complete.address = hostname_to_ip.at(info.host_name);
          complete.has_a = true;
        } else {
          std::string alt_host = info.host_name;
          if (!alt_host.empty() && alt_host.back() == '.') alt_host.pop_back();
          if (hostname_to_ip.count(alt_host)) {
            complete.address = hostname_to_ip.at(alt_host);
            complete.has_a = true;
          }
        }
      }
      result[info.instance_name] = complete;
    }
  }
  return result;
}

std::map<std::string, ServiceInfo> mDNS::executeDiscovery() {
  ServiceDiscoveryContext ctx;
  int sockets[32];
  int num_sockets = openClientSockets(sockets, sizeof(sockets) / sizeof(sockets[0]), 0);
  if (num_sockets <= 0) {
    MDNS_LOG << "Failed to open any client sockets\n";
    return {};
  }
  size_t capacity = 2048;
  void *buffer = malloc(capacity);
  for (int isock = 0; isock < num_sockets; ++isock) {
    mdns_discovery_send(sockets[isock]);
  }
  auto start = std::chrono::steady_clock::now();
  bool running = true;
  while (running) {
    for (int isock = 0; isock < num_sockets; ++isock) {
      mdns_query_recv(sockets[isock], buffer, capacity, discovery_query_callback, &ctx, 0);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    if (elapsed > 5000) { // 5 seconds
      running = false;
    }
  }
  free(buffer);
  for (int isock = 0; isock < num_sockets; ++isock) {
    mdns_socket_close(sockets[isock]);
  }
  // Build a hostname->IP map from all A records
  std::map<std::string, std::string> hostname_to_ip;
  for (const auto& [key, info] : ctx.services) {
    if (!info.host_name.empty() && !info.address.empty() && info.has_a) {
      hostname_to_ip[info.host_name] = info.address;
    }
  }
  std::map<std::string, ServiceInfo> result;
  for (const auto& [key, info] : ctx.services) {
    if (info.has_ptr && info.has_srv && info.has_txt) {
      ServiceInfo complete = info;
      if (!info.host_name.empty()) {
        if (hostname_to_ip.count(info.host_name)) {
          complete.address = hostname_to_ip.at(info.host_name);
          complete.has_a = true;
        } else {
          std::string alt_host = info.host_name;
          if (!alt_host.empty() && alt_host.back() == '.') alt_host.pop_back();
          if (hostname_to_ip.count(alt_host)) {
            complete.address = hostname_to_ip.at(alt_host);
            complete.has_a = true;
          }
        }
      }
      result[info.instance_name] = complete;
    }
  }
  return result;
}

void mDNS::runDumpMode(int *sockets, const int num_sockets) {
  printf("Opened %d socket%s for mDNS dump\n", num_sockets, num_sockets > 1 ? "s" : "");
  size_t capacity = 2048;
  void *buffer = malloc(capacity);
  // This is a crude implementation that checks for incoming queries and answers
  while (running_) {
    int nfds = 0;
    fd_set readfs;
    FD_ZERO(&readfs);
    for (int isock = 0; isock < num_sockets; ++isock) {
      if (sockets[isock] >= nfds) nfds = sockets[isock] + 1;
      FD_SET(sockets[isock], &readfs);
    }
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 100000;
    if (select(nfds, &readfs, 0, 0, &timeout) >= 0) {
      for (int isock = 0; isock < num_sockets; ++isock) {
        if (FD_ISSET(sockets[isock], &readfs)) {
          mdns_socket_listen(sockets[isock], buffer, capacity, dump_callback, 0);
        }
        FD_SET(sockets[isock], &readfs);
      }
    } else {
      break;
    }
  }
  free(buffer);
  for (int isock = 0; isock < num_sockets; ++isock) mdns_socket_close(sockets[isock]);
  printf("Closed socket%s\n", num_sockets > 1 ? "s" : "");
}

}  // namespace mdns_cpp
