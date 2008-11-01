/*
 * -----------------------------------------------
 * capture.h
 *
 *  Created on: Nov 1, 2008
 *      Author: sorin
 * -----------------------------------------------
 */

#include <pcap.h>
#include "iprestrict.h"

#ifndef CAPTURE_H_
#define CAPTURE_H_

/* IP header */
typedef struct {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        ipr_ip_t ip_src,ip_dst;  /* source and dest address */
} sniff_ip_t;

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

extern void got_packet(u_char *user, struct pcap_pkthdr *phrd, u_char *pdata);

#endif /* CAPTURE_H_ */
