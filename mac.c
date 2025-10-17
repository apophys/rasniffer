/*
 * mac.c
 * Author: Milan Kubík, xkubik17@stud.fit.vutbr.cz
 * Date: November 2010
 *
 * Description:
 *  
 *  extracts MAC address of given interface name
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>
#ifndef __linux__
#include <net/if_dl.h>
#include <sys/sysctl.h>
#else
#include <linux/sysctl.h>
#endif // __linux__
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mac.h"


/* 
 * Function gets MAC address of used NIC (interface)
 *
 * Works on both linux and freeBSD
 *
 * On error returns -1
 *
 */
int get_mac_address(unsigned char address[], const char *name)
{
#ifdef __linux__
  // open socket 
  int fd; 
  if((fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket - cmp mac");
    return -1;
  }

  // prepare structs for interface request
  struct ifreq if_req;
  memset(&if_req, 0, sizeof(if_req));
  
  strncpy(if_req.ifr_name, name, IF_NAMESIZE);

  // get the HW address
  if (ioctl(fd, SIOCGIFHWADDR, &if_req) != 0) {
    perror("ioctl - hw addr");
    return -1;
  }
  close(fd);

  memcpy(address, if_req.ifr_hwaddr.sa_data, 6);
#elif __FreeBSD__ || __APPLE__
  int mib[6];
  size_t len;
  char *buf;
  unsigned char *ptr;
  struct if_msghdr *ifm;
  struct sockaddr_dl *sdl;

  mib[0] = CTL_NET;
  mib[1] = AF_ROUTE;
  mib[2] = 0;
  mib[3] = AF_LINK;
  mib[4] = NET_RT_IFLIST;
  
  if ((mib[5] = if_nametoindex(name)) == 0) {
    perror("if_nametoindex error");
    return -1;
  }

  if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
    perror("sysctl 1 error");
    return -1;
  }

  if ((buf = malloc(len)) == NULL) {
    perror("malloc error");
    return -1;
  }

  if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
    perror("sysctl 2 error");
    return -1;
  }

  ifm = (struct if_msghdr *)buf;
  sdl = (struct sockaddr_dl *)(ifm + 1);
  ptr = (unsigned char *)LLADDR(sdl);

  memcpy(address, ptr, 6);
  free(buf);
#endif // ifndef linux
  
  return 0;
}

