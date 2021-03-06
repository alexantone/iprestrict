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

#define IFCONFIG "/sbin/ifconfig"

void if_up(const char * const interface,
           const unsigned int subinterface,
           const ipr_ip_t ip)
{
    char * cmd[256];
    sprintf(cmd, IFCONFIG" %s:%d %d.%d.%d.%d netmask 255.255.255.255 &> /dev/null",
            interface, subinterface,
            ip.ip_dd[0], ip.ip_dd[1], ip.ip_dd[2], ip.ip_dd[3]);

    if (system(cmd) != 0) {
        fprintf(stderr,
                " [!] Could not produce collison for ip: %d.%d.%d.%d on iterface %s:%d\n",
                ip.ip_dd[0], ip.ip_dd[1], ip.ip_dd[2], ip.ip_dd[3],
                interface, subinterface);
    } else {
        fprintf(stdout,
                " Blocked ip: %d.%d.%d.%d by colliding on iterface %s:%d\n",
                ip.ip_dd[0], ip.ip_dd[1], ip.ip_dd[2], ip.ip_dd[3],
                interface, subinterface);
    }
    fflush(stdout);
    fflush(stderr);
}

void if_down(const char * const interface,
             const unsigned int subinterface)
{
    char * cmd[256];
    sprintf(cmd, IFCONFIG" %s:%d down &> /dev/null",
            interface, subinterface);

    if (system(cmd) != 0) {
        fprintf(stderr,
                " [!] Some error has occured when shutting down iterface %s:%d\n",
                interface, subinterface);
    } else {
        fprintf(stdout,
                " Released iterface %s:%d\n",
                interface, subinterface);
    }
    fflush(stdout);
    fflush(stderr);
}

void if_all_down(const char * const interface)
{
    char * cmd[256];
    sprintf(cmd, "{ for ix in `"IFCONFIG" |grep %s: | cut -d ' ' -f 1` ; do "IFCONFIG" $ix down; done } &> /dev/null",
                 interface);
    system(cmd);
    fflush(stdout);
    fflush(stderr);
}
void block_ip(const ipr_ip_t ip)
{
    int ix = 0;
    int found_if = 0;
    long last_free_if = -1;
    unsigned int smallest_ttl = MAX_TTL;
    unsigned int smallest_ttl_if = 0;



    for (ix = 0; ix < MAX_SUBINTERFACES; ix++) {
        if (subif_table[ix].inuse) {
            if (subif_table[ix].ip.ip_v == ip.ip_v) {
                found_if = 1;
                subif_table[ix].ttl = MAX_TTL;
                break;
            } else {

                /*
                 * Decrease the TTL and disable it if reached 0.
                 */
                subif_table[ix].ttl--;

                if (subif_table[ix].ttl < smallest_ttl) {
                    smallest_ttl = subif_table[ix].ttl;
                    smallest_ttl_if = ix;
                }

                if (subif_table[ix].ttl == 0) {
                    subif_table[ix].inuse = FALSE;
                    if_down(dev, subif_table[ix].id);
                    last_free_if = ix;
                }

            }
        }
        else if (last_free_if < 0) {
            last_free_if = ix;
        }
    }

    if (!found_if) {
        /*
         * if there is no free interface use the one whith the smallest ttl
         * (which is the oldest one).
         * No need to put it down first; it will be directly overwritten.
         */
        if (last_free_if < 0) {
            if_up(dev, subif_table[smallest_ttl_if].id, ip);
        }
        /*
         * Use the last free interface and enable it setting the TTL to max.
         */
        else {
            subif_table[last_free_if].inuse = TRUE;
            subif_table[last_free_if].id = last_free_if;
            subif_table[last_free_if].ip.ip_v = ip.ip_v;
            subif_table[last_free_if].ttl = MAX_TTL;
            if_up(dev, last_free_if, ip);

        }
    }
}
