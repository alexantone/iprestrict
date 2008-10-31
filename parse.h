/*
 * -----------------------------------------------
 * parse.h
 *
 *  Created on: Oct 30, 2008
 *      Author: sorin
 * -----------------------------------------------
 */

#ifndef PARSE_H_
#define PARSE_H_

static const char *default_locations[] = {
        "/etc/iprestrict.cfg",
        "iprestrict.cfg" };

static const int default_locations_cnt = sizeof(default_locations)
        / sizeof(default_locations[0]);

#define WHITESPACE_CHARS " \t\n"

#define BASE10 10
#define BASE16 16

#define RULE_DENY    0x00
#define RULE_ALLOW   0x01

#define RULE_RANGE   0x01
#define RULE_SUBNET  0x02
#define RULE_IP      0x03
#define RULE_ALL     0x04

#define MAX_MASK_BYTES 32

/*
 * Rules structures
 */

#define MAX_ENTRIES 1024

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

extern ipr_rule_t * rule_table[];
extern int rule_cnt;

extern int parse_args (const int argc, char * const argv[],
                       FILE ** p_fh, char ** p_ifdev);

extern int parse_range(const char * const token, ipr_range_t * const out);
extern int parse_subnet(const char* const token, ipr_subnet_t * const out);
extern int parse_file(FILE ** p_fh);

#endif /* PARSE_H_ */
