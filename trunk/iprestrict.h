/*
 * iprestrict.h
 *
 *  Created on: Oct 24, 2008
 *      Author: sorin
 */

#ifndef IPRESTRICT_H_
#define IPRESTRICT_H_

#define RULE_DENY  0x00
#define RULE_ALLOW 0x01

#define RULE_RANGE   0x01
#define RULE_SUBNET  0x02
#define RULE_IP      0x03
#define RULE_ALL     0x04

#define MAX_MASK_BYTES 32

typedef union {
    unsigned char ip_dd[4];
    long int      ip_v;
} ipr_ip_t;

typedef struct {
    ipr_ip_t start;
    ipr_ip_t stop;
} ipr_range_t;

typedef struct {
    ipr_ip_t      ip;
    unsigned char mask;
} ipr_subnet_t;

typedef union {
    ipr_range_t     range;
    ipr_subnet_t    subnet;
    ipr_ip_t            ip;
} ipr_format_t;

typedef struct {
    unsigned char permission;
    unsigned char type;
    ipr_format_t  match;
} ipr_rule_t;

#define MAX_ENTRIES 1024


#endif /* IPRESTRICT_H_ */
