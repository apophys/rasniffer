/**
 * rasniffer.c
 * Author: Milan Kubík, xkubik17@stud.fit.vutbr.cz
 * Date: October 2010
 *
 * Description:
 * Initialize pcap, set NIC into promisc mode.
 *
 * If set, send one Router Solicitation packet
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <pcap/pcap.h>

#include "params.h"
#include "sender.h"
#include "sniffer.h"

#ifndef PCAP_NETMASK_UNKNOWN
#define PCAP_NETMASK_UNKNOWN 0
#endif

pcap_t *handle = NULL;

void sigint_handler(int sig);

int main(int argc, char *argv[])
{
  struct params_t options;
  int retval;

  if (argc < 3) {
    fprintf(stdout, "Usage: %s -i <interface> [-r] [-s]\n", argv[0]);
    return EXIT_SUCCESS;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  const char pcap_filter[] = "icmp6"; // TODO optimalizovat filter?

  // pcap_t *handle = NULL;
  struct bpf_program fp;
  const int timeout = 10500;

  memset(&options, 0, sizeof(options));

  retval = parse_params(argc, argv, &options);

  if (options.solicit == true)
    send_rs_packet(options.interface);

  handle = pcap_open_live(options.interface, BUFSIZ, 1, timeout, errbuf);

  if (handle == NULL) {
    fprintf(stderr, "%s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  if (pcap_compile(handle, &fp, pcap_filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
    fprintf(stderr, "Couldn't parse filter. %s: %s\n", pcap_filter, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't set filter %s: %s\n", pcap_filter, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  signal(SIGINT, sigint_handler);

  pcap_loop(handle, 0, got_packet, (u_char *) &options); // infinite loop

  return EXIT_SUCCESS;
}

void sigint_handler(int sig)
{
  pcap_breakloop(handle);
}
