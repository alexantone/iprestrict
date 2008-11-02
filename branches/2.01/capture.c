/*
 * -----------------------------------------------
 * capture.c
 *
 *  Created on: Nov 1, 2008
 *      Author: sorin
 * -----------------------------------------------
 */

#include "iprestrict.h"
#include "capture.h"
#include "subinterface.h"

static void process_ip(const unsigned char permision, const ipr_ip_t ip)
{
    if (permision == RULE_DENY) {
        block_ip(ip);
    }
    /*
     * else no need to do anything
     */

}


/*
 * Find the applying rule
 */
static void check_ip(ipr_ip_t ip)
{
    int ix = 0;

    for (ix = 0; ix < rule_cnt; ix++){
        switch(rule_table[ix]->type) {
        case RULE_ALL:
            process_ip(rule_table[ix]->permission, ip);
            return;
            break;
        case RULE_IP:
            if (rule_table[ix]->match.ip.ip_v == ip.ip_v) {
                process_ip(rule_table[ix]->permission, ip);
                return;
            }
            break;
        case RULE_RANGE:
            if (ip_val(rule_table[ix]->match.range.start) <= ip_val(ip) &&
                ip_val(rule_table[ix]->match.range.stop) >= ip_val(ip)) {
                process_ip(rule_table[ix]->permission, ip);
                return;
            }
            break;
        case RULE_SUBNET:
            if (((ip_val(ip) ^ ip_val(rule_table[ix]->match.subnet.ip)) &
                  (0xffffffff << (32 - rule_table[ix]->match.subnet.mask))) == 0) {
                process_ip(rule_table[ix]->permission, ip);
                return;
            }
            break;
        default:
            fprintf(stderr, "There is a corrupt entry in the rule table!\n");
            break;
        }
    }
}


void got_packet(u_char *args, struct pcap_pkthdr *phrd, u_char *pdata)
{
    check_ip(((sniff_ip_t*)(pdata + ETHERNET_HEADER_LEN))->ip_src);
}


