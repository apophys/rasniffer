/**
 * sniffer.h
 * Author: Milan Kubík, xkubik17@stud.fit.vutbr.cz
 * Date: October 2010
 *
 * Description:
 * in sniffer.c
 */
#ifndef __SNIFFER_H
#define __SNIFFER_H

#include <pcap/pcap.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                const u_char *packet);
#endif // __SNIFFER_H
