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
#include <signal.h>

#include <pcap.h>

#include "iprestrict.h"
#include "parse.h"
#include "capture.h"
#include "subinterface.h"

static FILE *fh = NULL;                    /* config file handle */
static pcap_t *handle = NULL;              /* packet capture handle */

char *dev = NULL;

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

#if DEBUG
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
#endif

/*
 * Memory freeing routine and cleanup before exiting
 */
void do_cleanup(void) {

    int ix = 0;

    if (dev != NULL) {
        if_all_down(dev);
    }

    if (fh != NULL) {
        fclose(fh);
    }

    if (handle != NULL) {
        pcap_close(handle);
    }

    for (ix = 0; ix < rule_cnt; ix++) {
        if (rule_table[ix] != NULL) {
            free(rule_table[ix]);
        }
    }
}


static int terminate(int param){
    do_cleanup();
    fprintf(stdout, "\n  Exiting program...\n");
    exit(EXIT_FAILURE);
}


int main (int argc, char *argv[])
{

    memset(rule_table, 0, sizeof(rule_table));
    memset(subif_table, 0, sizeof(subif_table));

    rule_cnt = 0;
    int exit_code = EXIT_SUCCESS;
    int pargs_result = 0;

    /*
     * Register function for signal handling
     */
    signal(SIGABRT,terminate);
    signal(SIGTERM,terminate);
    signal(SIGINT, terminate);
    signal(SIGKILL,terminate);

    pargs_result = parse_args(argc, argv, &fh, &dev);
    if (pargs_result != 0) {
        /*
         * parse_args() could have returned 1 which means
         * that the usage message was requested.
         */
        exit_code = (pargs_result == 1) ? EXIT_SUCCESS : EXIT_FAILURE;
        goto cleanup;
    } else


    if (parse_file(&fh) != 0) {
        exit_code = EXIT_FAILURE;
        goto cleanup;
    }

    fprintf(stdout,
            "  ... Parsing of file was scucessuful. "
            "Number of rules in effect: %d\n", rule_cnt);

#if DEBUG
    dbg_dumprules();
#endif

    /*
     * Main program loop
     */

    char   errbuf[PCAP_ERRBUF_SIZE];      /* error buffer */



    /* find a capture device if not specified on command-line */
    if (dev == NULL) {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n",
                    errbuf);
            exit_code = EXIT_FAILURE;
            goto cleanup;
        }
    }

    /* open capture device timeout = 1sec */
    handle = pcap_open_live(dev, ETHERNET_HEADER_LEN + IP_HEADER_LEN,
                            TRUE, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit_code = EXIT_FAILURE;
        goto cleanup;
    }

    /*
     * Avoid blocking own ip by setting an "allow ip <own ip>" rule
     */

    /*
     * TODO: find a way to get the device's ip
     */

    /*
     * Clear possible active subinterfaces
     */
    if_all_down(dev);
    fprintf(stdout, "\n  Hit ^C to stop the program.\n\n");

    /* now we can set our callback function */
    pcap_loop(handle, -1, got_packet, NULL);

    /* cleanup */
cleanup:
    do_cleanup();

    fprintf(stdout, "\n  Exiting program...\n");

    return exit_code;
}
