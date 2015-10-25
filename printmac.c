#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mac.h"

int main(int argc, char *argv[])
{
    if (argc != 2) return EXIT_FAILURE;

    char *interface = argv[1];

    unsigned char address[6];
    memset(address, 0, 6);
    unsigned char *pt = address;

    int i = 0;

    i = get_mac_address(address, interface);
    if (i != 0) {
        fprintf(stderr, "Could not retrieve the address\n");
        return EXIT_FAILURE;
    }

    printf("Printing mac address of interface %s\n", interface);
    printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
            pt[0], pt[1], pt[2], pt[3],
            pt[4], pt[5]);

    return 0;

}
