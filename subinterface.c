/*
 * ------------------------------------------------------------------------
 * subinterface.c
 *
 *  Created on: Oct 31, 2008
 *      Author: alex
 * ------------------------------------------------------------------------
 */

#include <stdlib.h>
#include <stdio.h>

#include "subinterface.h"

void if_up(const char * const interface,
           const unsigned int subinterface,
           const ipr_ip_t ip)
{
    char * cmd[256];
    sprintf(cmd,"ifconfig %s:%d %d.%d.%d.%d netmask 255.255.255.255",
            interface, subinterface,
            ip.ip_dd[0], ip.ip_dd[1], ip.ip_dd[2], ip.ip_dd[3]);

    if (system(cmd) != 0) {
        fprintf(stderr,
                " [!] Could not produce collison for ip: %d.%d.%d.%d on iterface %s:%d",
                ip.ip_dd[0], ip.ip_dd[1], ip.ip_dd[2], ip.ip_dd[3],
                interface, subinterface);
    } else {
        fprintf(stdout,
                " Blocked ip: %d.%d.%d.%d by colliding on iterface %s:%d",
                ip.ip_dd[0], ip.ip_dd[1], ip.ip_dd[2], ip.ip_dd[3],
                interface, subinterface);
    }
}

void if_down(const char * const interface,
             const unsigned int subinterface)
{
    char * cmd[256];
    sprintf(cmd,"ifconfig %s:%d down",
            interface, subinterface);

    if (system(cmd) != 0) {
        fprintf(stderr,
                " [!] Some error has occured when shutting down iterface %s:%d",
                interface, subinterface);
    } else {
        fprintf(stdout,
                " Released iterface %s:%d",
                interface, subinterface);
    }


}

void block_ip(const ipr_ip_t ip)
{
    /*
     * TODO: impelemtation
     */
}
