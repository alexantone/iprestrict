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

#include "iprestrict.h"
#include "parse.h"
#include "subinterface.h"

static FILE *fh = NULL;
static char *ifdev = NULL;

ipr_rule_t* rule_table[MAX_ENTRIES];
int rule_cnt = 0;

dev_sif_t subif_table[MAX_SUBINTERFACES];


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
    
    for (ix = 0; ix < rule_cnt; ix++) {
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

    if (parse_args(argc, argv, &fh, &ifdev) !=  0) {
        exit_code = -1;
        goto cleanup;
    }

    if (parse_file(&fh) != 0) {
        exit_code = -1;
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
    while (1) {
        
    }
    
cleanup:
    do_cleanup();

    return exit_code;
}
