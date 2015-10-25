/**
 * sender.h
 * Author: Milan Kubík, xkubik17@stud.fit.vutbr.cz
 * Date: October 2010
 *
 */

#ifndef __SENDER_H
#define __SENDER_H

#include <stdbool.h>

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include "params.h"

int send_ra_packet(const struct icmp6_hdr *src, unsigned len, const char *iface);
int send_rs_packet(const char *iface);
int send_packet(const void *src, unsigned len, const char *iface, const char *address, bool solicit);

#endif // __SENDER_H
