/**
 * sniffer.c
 * Author: Milan Kubík, xkubik17@stud.fit.vutbr.cz
 * Date: October 2010
 *
 * Description:
 * - packet filter for sniffing Router Advertisement
 *   and posibly Router solicitation ICMPv6 packets
 *
 * - Prints informations from RA packets.
 *   - source and destination address
 *   - router lifetime, reachable time, retrans counter, flags
 *   - Prefix information:
 *     - valid & preferred lifetime
 *     - prefix, prefix length
 *     - flags
 *   - MTU
 *
 * - If selected, sends it's own RA packet
 */
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include "mac.h"
#include "sender.h"
#include "sniffer.h"

static struct icmp6_hdr* strip_ip_hdr(const struct ip6_hdr *data);

static void parse_ra_flags(uint8_t flags);
static void print_info(const struct ip6_hdr *ip6_head, const struct nd_router_advert *icmp6);
static void print_prefix_info(const struct nd_opt_prefix_info *option);
static void print_mtu_info(const struct nd_opt_mtu *option);
static void print_link_layer_info(const u_char *option);

static int compare_mac_addresses(const u_char *header, const char *name);

#define RA_PREF_HIGH 0x08
#define RA_PREF_MEDIUM 0x00
#define RA_PREF_LOW 0x18
#define RA_PREF_RESERVED 0x10

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif // bsd ...


/*
 * Callback function for pcap_loop
 *
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
  struct params_t *params = (struct params_t *) args;

  /* jump over ethernet header */
  const struct ip6_hdr *ip6;
  struct icmp6_hdr *icmp6;

  ip6 = (struct ip6_hdr *) (packet + ETH_HLEN);
  if ((icmp6 = strip_ip_hdr(ip6)) == NULL)
    return;

  unsigned payload_len = ntohs(ip6->ip6_plen);

  if (icmp6->icmp6_type == ND_ROUTER_ADVERT) {
    // Print information about captured packet
    print_info(ip6, (struct nd_router_advert *) icmp6);

    // send own packet with low priority
    bool send_pckt = params->emit;
    if (send_pckt) {
      int cmp = compare_mac_addresses((const u_char *) packet, params->interface);

      if (cmp == -1) {
        fprintf(stderr, "Interface error\n");
        exit(EXIT_FAILURE);
      }

      if (cmp == 1) // source MAC is mine...
        return;     // else, send modified packet

      if (send_ra_packet(icmp6, payload_len, params->interface) != 0) {
        // ERROR handling
        fprintf(stderr, "Couldn't send packet.\n");
      }
    }
  }
}

/*
 * Function takes one uint8_t number containing flags
 * and parses it.
 *
 */
static void parse_ra_flags(uint8_t flags)
{
  fprintf(stdout, "\tFlags: %s", (flags & 0xe4)?"":"none");

  if (flags & ND_RA_FLAG_MANAGED) fprintf(stdout, "managed, ");
  if (flags & ND_RA_FLAG_OTHER) fprintf(stdout, "other, ");

#ifdef ND_RA_FLAG_HOME_AGENT
  if (flags & ND_RA_FLAG_HOME_AGENT)
#else
  if (flags & ND_RA_FLAG_HA)
#endif // bsd
    fprintf(stdout, "home agent, ");
  if (flags & 0x04) // experimental flag
    fprintf(stdout, "proxied");

  char *pref = NULL;

  uint8_t ra_pref = flags;
  ra_pref &= 0x18; // b00011000

  switch (ra_pref) { // hex values represents strings prefs.
    case RA_PREF_MEDIUM:
      pref = "medium";
      break;

    case RA_PREF_HIGH:
      pref = "high";
      break;

    case RA_PREF_LOW:
      pref = "low";
      break;

    case RA_PREF_RESERVED: // should not be received
      pref = "reserved";
      break;

    default:
      break;
  }

  fprintf(stdout, "\tRouter preference: %s\t", pref);
}


/*
 * Prints information from captured packet.
 *
 * Source and dest. addresses, router lifetime,
 * more info at the begining of file.
 *
 */
static void print_info(const struct ip6_hdr *ip6_head, const struct nd_router_advert *icmp6)
{
  unsigned len = ntohs(ip6_head->ip6_plen);

  // address info
  char src_addr[INET6_ADDRSTRLEN], dst_addr[INET6_ADDRSTRLEN];

  if (inet_ntop(AF_INET6, &ip6_head->ip6_src, src_addr, sizeof(src_addr)) == NULL)
    perror("inet_ntop");

  if (inet_ntop(AF_INET6, &ip6_head->ip6_dst, dst_addr, sizeof(dst_addr)) == NULL)
    perror("inet_ntop");

  fprintf(stdout, "Source address:\t\t%s\t\t", src_addr);
  fprintf(stdout, "Destination address:\t%s\n", dst_addr);

  // options from header, bit fields, etc.
  uint8_t hop_limit = icmp6->nd_ra_curhoplimit;
  uint8_t flags = icmp6->nd_ra_flags_reserved;
  uint16_t router_lifetime = ntohs(icmp6->nd_ra_router_lifetime);
  uint32_t reachable = ntohl(icmp6->nd_ra_reachable);
  uint32_t retransmit = ntohl(icmp6->nd_ra_retransmit);

  fprintf(stdout, "hop limit %u,", (unsigned) hop_limit);
  parse_ra_flags(flags);
  fprintf(stdout, "router lifetime: %us\n", (unsigned) router_lifetime);
  fprintf(stdout, "reachable time: %us, retransmit time: %us\n", reachable, retransmit);

  len -= sizeof(struct nd_router_advert);
  struct nd_opt_hdr *option = (struct nd_opt_hdr *) ((u_char *) icmp6 + sizeof(struct nd_router_advert));

  while (len > 0) {
    u_char type = option->nd_opt_type;

    switch (type) {
      case ND_OPT_PREFIX_INFORMATION:
  print_prefix_info((struct nd_opt_prefix_info *) option);
  break;

      case ND_OPT_MTU:
  print_mtu_info((struct nd_opt_mtu *) option);
  break;

      case ND_OPT_SOURCE_LINKADDR:
      case ND_OPT_TARGET_LINKADDR:
  print_link_layer_info((const u_char *) option);
  break;

      default:
  fprintf(stderr, "Unknown / unimplemented option.\n");
  break;
    }
    len = len - option->nd_opt_len * 8; // len in bytes
    option = (struct nd_opt_hdr *) ((u_char *) option + option->nd_opt_len * 8);
  }

  fprintf(stdout, "==========\n\n");
}


/*
 * Prints information from prefix RA option
 *
 */
static void print_prefix_info(const struct nd_opt_prefix_info *option)
{
  fprintf(stdout, "Prefix info\tlength: %u\t", option->nd_opt_pi_len * 8);

  char *onlink = ((option->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ONLINK) > 0) ? "onlink" : "";
  char *autonomous = ((option->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO) > 0) ? "auto" : "";

  fprintf(stdout, "Flags: %s, %s\n", onlink, autonomous);
  fprintf(stdout, "Valid lifetime: %u, Preferred lifetime %u\t",
          ntohl(option->nd_opt_pi_valid_time), ntohl(option->nd_opt_pi_preferred_time));
  char prefix[INET6_ADDRSTRLEN];
  if (inet_ntop(AF_INET6, &option->nd_opt_pi_prefix, prefix, sizeof(prefix)) == NULL)
    perror("inet_ntop - prefix");
  fprintf(stdout, "Prefix: %s\n", prefix);
}


/*
 * Prints MTU info from this option
 */
static void print_mtu_info(const struct nd_opt_mtu *option)
{
  fprintf(stdout, "MTU: %u\n", ntohl(option->nd_opt_mtu_mtu));
}


static void print_link_layer_info(const u_char *option)
{
  uint8_t type = (uint8_t) *option;
  // uint8_t len = (uint8_t) *(option + 1);

  char addr[18]; // considering ethernet only
  const u_char *base = option + 2;
  sprintf(addr, "%02X:%02X:%02X:%02X:%02X:%02X",
    base[0], base[1], base[2], base[3], base[4], base[5]);

  if (type == ND_OPT_SOURCE_LINKADDR)
    fprintf(stdout, "Source link-layer address: %s\n", addr);
  else if (type == ND_OPT_TARGET_LINKADDR)
    fprintf(stdout, "Target link-layer address: %s\n", addr);
  else
    fprintf(stderr, "Sem by som nemal nikdy prist.\n");

}

/*
 * Function takes an u_char* address of ip header,
 * jumps over it and posibly extension headers and reurns
 * address of icmp header
 *
 * does not check extension headers itself
 */
static struct icmp6_hdr* strip_ip_hdr(const struct ip6_hdr *data)
{
  struct ip6_ext *curr = NULL;
  struct ip6_hdr *pckt = (struct ip6_hdr *) data;

  if (pckt == NULL)
    return NULL;

  // if next header is ICMP, return addr + lenght of header
  if (pckt->ip6_nxt == IPPROTO_ICMPV6)
    return (struct icmp6_hdr *) ((u_char *) data + sizeof(struct ip6_hdr));
  else { // jump over headers until next is ICMP
    curr = (struct ip6_ext *) ((u_char *) data + sizeof(struct ip6_hdr));

    while (curr->ip6e_nxt != IPPROTO_ICMPV6) {
      if (curr->ip6e_nxt == IPPROTO_FRAGMENT) {
  fprintf(stderr, "Fragment header found.\n");
  return NULL;
      }
      curr = (struct ip6_ext *) ((u_char *) curr + curr->ip6e_len);
    }

    curr = (struct ip6_ext *) ((u_char *) curr + curr->ip6e_len); // jump over last header
  }

  return (struct icmp6_hdr *) curr;
}


/*
 * Function takes ethernet frame as source for sender's MAC address
 * gets MAC of currently used NIC and compares those two.
 *
 * On error returns -1
 *
 */
static int compare_mac_addresses(const u_char *header, const char *name)
{
  unsigned char my_addr[8];
  memset(my_addr, 0, 8);

  if (get_mac_address(my_addr, name) == -1)
    return -1;

  int result = memcmp((void *) my_addr, (u_char *) (header + 6), 6);

  return (result == 0) ? 1 : 0;
}
