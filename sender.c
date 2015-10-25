/**
 * sender.c
 * Author: Milan Kubík, xkubik17@stud.fit.vutbr.cz
 * Date: October 2010
 *
 * Description:
 * sends modified packet to all local nodes
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "mac.h"
#include "sender.h"


static inline void modify_priority(struct nd_router_advert *message, const uint8_t pref);

/*
static const uint8_t RA_LOW_PREF = 0x18;
static const uint8_t RA_HIGH_PREF = 0x08;
static const uint8_t RA_MED_PREF = 0x00;
*/
enum {
    RA_LOW_PREF = 0x18,
    RA_HIGH_PREF = 0x08,
    RA_MED_PREF = 0x00,
} RA_MODE;

/*
 * Function takes pointer to the begining of captured ICMPv6 packet, sending it
 * after modification.
 *
 */
int send_ra_packet(const struct icmp6_hdr *src, unsigned len, const char *iface)
{
  struct icmp6_hdr *data;
  if ((data = malloc(len * sizeof(u_char))) == NULL) {
    fprintf(stderr, "malloc error");
    return -1;
  }
  // u_char data[len * sizeof(u_char)];
  memcpy(data, src, len * sizeof(u_char));

  // modify flags
  modify_priority((struct nd_router_advert *) data, RA_LOW_PREF);

  send_packet((void *) data, len * sizeof(u_char), iface, "ff02::1", false);

  free(data);

  return 0;
}


/*
 * Function sends Router Solicitation packet
 * with Source-link address set to MAC address
 * of NIC identified by iface.
 *
 */
int send_rs_packet(const char *iface)
{
  // create Router Solicitation header
  struct nd_router_solicit solicit;
  memset(&solicit, 0, sizeof(solicit));

  solicit.nd_rs_type = ND_ROUTER_SOLICIT;
  solicit.nd_rs_code = 0;

  // get MAC address
  unsigned char source_link[8];
  memset(source_link, 0, sizeof(source_link));
  source_link[0] = ND_OPT_SOURCE_LINKADDR;
  source_link[1] = 1; // 1 (* 8) octets
  get_mac_address(&source_link[2], iface);

  // join all together
  unsigned len = (unsigned) (sizeof(solicit) + sizeof(source_link));
  unsigned char *data = NULL;

  if ((data = malloc(len)) == NULL) {
    fprintf(stderr, "malloc error\n");
    return -1;
  }

  // prepare packet
  memcpy((void *) data, &solicit, sizeof(solicit));
  memcpy((void *) (data + sizeof(solicit)), (void *) source_link, sizeof(source_link));

  // ff02::2 all routers - for router solicitation
  if (send_packet(data, len, iface, "ff02::2", true) == -1) {
    fprintf(stderr, "Cannot send router solicitation.\n");
    free(data);
    return -1;
  }

  free(data);
  return 0;
}


/*
 * Function takes data of length 'len' from src address and send them to
 * given multicast address.
 *
 * If solicit is set to true, packet HOP LIMIT is set to 255.
 *
 * On error returns -1
 *
 */
int send_packet(const void *src, unsigned len, const char *iface, const char *address, bool solicit)
{
  int sockfd = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if (sockfd == -1) {
    perror("socket");
    return 1;
  }

  unsigned index = if_nametoindex(iface);
  const int on = 0;

  if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &index, sizeof(index)) == -1)
      perror("setsockopt - mcast if");
  if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on, sizeof(on)) == -1)
    perror("setsockopt - mcast loop");

  int hops = 255;
  if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) == -1)
    perror("setsockopt - max hops");

  // send
  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(addr));

  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(IPPROTO_ICMPV6); // next header  == icmp

  if (inet_pton(AF_INET6, address, &addr.sin6_addr) == -1) {
    perror("pton");
    return -1;
  }

  if (sendto(sockfd, src, len * sizeof(u_char), 0,
	     (const struct sockaddr *) &addr, sizeof(addr)) == -1) {
    perror("sendto");
    close(sockfd);
    return -1;
  }

  close(sockfd);
  return 0;
}


/*
 * Modify router preference bits
 *
 */
static inline void modify_priority(struct nd_router_advert *message, const uint8_t pref)
{
  message->nd_ra_flags_reserved |= pref;
}
