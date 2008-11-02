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
        uint8_t  ip_vhl;                /* version << 4 | header length >> 2 */
        uint8_t  ip_tos;                /* type of service */
        uint16_t ip_len;                /* total length */
        uint16_t ip_id;                 /* identification */
        uint16_t ip_off;                /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        uint8_t ip_ttl;                 /* time to live */
        uint8_t ip_p;                   /* protocol */
        uint16_t ip_sum;                /* checksum */
        ipr_ip_t ip_src;                /* source and dest address */
        ipr_ip_t ip_dst;
} sniff_ip_t;

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

extern void got_packet(u_char *args, struct pcap_pkthdr *phrd, u_char *pdata);

#endif /* CAPTURE_H_ */
