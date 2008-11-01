/*
 * --------------------------------------------------------------------
 * iprestrict.c
 *
 *  Created on: Oct 24, 2008
 *      Author: sorin
 * --------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "iprestrict.h"
#include "parse.h"
#include "subinterface.h"
#include "capture.h"

static FILE *fh = NULL;
static char *dev = NULL;

ipr_rule_t* rule_table[MAX_ENTRIES];
int rule_cnt = 0;

dev_sif_t subif_table[MAX_SUBINTERFACES];

inline uint32_t ip_val(ipr_ip_t ip)
{
    return ((ip.ip_dd[0] << 24) |
            (ip.ip_dd[1] << 16) |
            (ip.ip_dd[2] <<  8) |
            (ip.ip_dd[3] <<  0));
}

void dbg_dumprules(void) {
    int ix;

    for (ix = 0; ix <= rule_cnt; ix++) {
        if (rule_table[ix] != NULL) {
            printf("  -> %s ",
                   rule_table[ix]->permission ? "allow" : "deny");
            switch(rule_table[ix]->type) {
                case RULE_IP:
                    printf("ip %d.%d.%d.%d\n",
                           rule_table[ix]->match.ip.ip_dd[0],
                           rule_table[ix]->match.ip.ip_dd[1],
                           rule_table[ix]->match.ip.ip_dd[2],
                           rule_table[ix]->match.ip.ip_dd[3]);
                    break;
                case RULE_RANGE:
                    printf("range %d.%d.%d.%d-%d.%d.%d.%d\n",
                           rule_table[ix]->match.range.start.ip_dd[0],
                           rule_table[ix]->match.range.start.ip_dd[1],
                           rule_table[ix]->match.range.start.ip_dd[2],
                           rule_table[ix]->match.range.start.ip_dd[3],
                           rule_table[ix]->match.range.stop.ip_dd[0],
                           rule_table[ix]->match.range.stop.ip_dd[1],
                           rule_table[ix]->match.range.stop.ip_dd[2],
                           rule_table[ix]->match.range.stop.ip_dd[3]);
                    break;
                case RULE_SUBNET:
                    printf("subnet %d.%d.%d.%d/%d\n",
                           rule_table[ix]->match.subnet.ip.ip_dd[0],
                           rule_table[ix]->match.subnet.ip.ip_dd[1],
                           rule_table[ix]->match.subnet.ip.ip_dd[2],
                           rule_table[ix]->match.subnet.ip.ip_dd[3],
                           rule_table[ix]->match.subnet.mask);
                    break;
                case RULE_ALL:
                    printf("all\n");
                    break;
                default:
                    printf("*** Some bad data was parsed ***");
            }
        }
    }

}

/*
 * Memory freeing routine and cleanup before exiting
 */
void do_cleanup(void) {

    int ix = 0;

    if (fh != NULL) {
        fclose(fh);
    }

    for (ix = 0; ix < rule_cnt; ix++) {
        if (rule_table[ix] != NULL) {
            free(rule_table[ix]);
        }
    }

    for (ix = 0; ix < MAX_SUBINTERFACES; ix++) {
        /*
         * TODO: Subinterfaces cleanup
         */
    }
}

int main (int argc, char *argv[])
{

    memset(rule_table, 0, sizeof(rule_table));
    memset(subif_table, 0, sizeof(subif_table));

    rule_cnt = 0;
    int exit_code = 0;

    if (parse_args(argc, argv, &fh, &dev) !=  0) {
        exit_code = 1;
        goto cleanup;
    }

    if (parse_file(&fh) != 0) {
        exit_code = 1;
        goto cleanup;
    }

    fprintf(stdout,
            "  ... Parsing of file was scucessuful. "
            "Number of rules in effect: %d\n",
            rule_cnt + 1);

    dbg_dumprules();

    /*
     * Main program loop
     */

    char   errbuf[PCAP_ERRBUF_SIZE];      /* error buffer */
    pcap_t *handle = NULL;		/* packet capture handle */



    /* find a capture device if not specified on command-line */
    if (dev == NULL) {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n",
                    errbuf);
            exit_code = 1;
            goto cleanup;
        }
    }

    /* open capture device timeout = 1sec */
    handle = pcap_open_live(dev, IP_HEADER_LEN, TRUE, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit_code = 1;
        goto cleanup;
    }


    /* now we can set our callback function */
    pcap_loop(handle, -1, got_packet, NULL);

    /* cleanup */
cleanup:
    pcap_close(handle);
    do_cleanup();

    return exit_code;
}
