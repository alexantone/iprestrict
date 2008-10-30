/*
 * --------------------------------------------------------------------
 * parse.c
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

int parse_ip (const char * const token, ipr_ip_t * const out) {

    int ix = 0;
    unsigned long temp_byte;
    char * cursor = token;

    memset(out, 0, sizeof(out));

    while (ix < 4) {
        temp_byte = strtoul(cursor, &cursor, BASE10);

        if (temp_byte > 255) {
            return -1;
        }

        if (*cursor != '.' && ix < 3) {
            return -2;
        }

        if (ix < 3) {
            cursor++;
        }
        
        out->ip_dd[ix] = temp_byte;
    }

    /*
     * There should not be any more chracters after the ip 
     * except for whitespace.
     */
    cursor += strspn(cursor, WHITESPACE_CHARS);
    if (*cursor != '\0') {
        return -3;
    }

    return 0;
}

/*
 * Range check function
 */

int parse_range (const char * const token, ipr_range_t * const out) {

    int ix = 0;
    unsigned long temp_byte;
    char * cursor = token;

    memset(out, 0, sizeof(out));

    /*
     * Parse the first ip.
     */
    while (ix < 4) {
        temp_byte = strtoul(cursor, &cursor, BASE10);

        if (temp_byte > 255) {
            return -1;
        }

        if (*cursor != '.' && ix < 3) {
            return -2;
        }

        if (ix < 3) {
            cursor++;
        }

        out->start.ip_dd[ix] = temp_byte;
    }
    
    if (*cursor != '-') {
        return -3;
    }

    /*
     * Parse the second ip.
     */
    ix = 0;
    while (ix < 4) {
        temp_byte = strtoul(cursor, &cursor, BASE10);

        if (temp_byte > 255) {
            return -1;
        }

        if (*cursor != '.' && ix < 3) {
            return -2;
        }

        if (ix < 3) {
            cursor++;
        }

        out->stop.ip_dd[ix] = temp_byte;
    }

    /*
     * There should not be any more chracters after the ip 
     * except for whitespace.
     */
    cursor += strspn(cursor, WHITESPACE_CHARS);
    if (*cursor != '\0') {
        return -3;
    }

    return 0;
}

/*
 *  Mask check function
 */

int parse_subnet (const char* const token, ipr_subnet_t * const out) {

    int ix = 0;
    unsigned long temp_byte;
    unsigned long temp_mask;
    char * cursor = token;

    memset(out, 0, sizeof(out));

    /*
     * Parse the subnet.
     */
    while (ix < 4) {
        temp_byte = strtoul(cursor, &cursor, BASE10);

        if (temp_byte > 255) {
            return -1;
        }

        if (*cursor != '.' && ix < 3) {
            return -2;
        }

        if (ix < 3) {
            cursor++;
        }

        out->ip.ip_dd[ix] = temp_byte;
    }
    
    if (*cursor != '/') {
        return -3;
    }

    cursor++;
    temp_mask = strtoul(cursor, &cursor, BASE10);
    if (temp_mask > MAX_MASK_BYTES) {
        return -4;
    }
    
    out->mask = temp_mask;
    
    return 0;

}

int parse_file (FILE *fh) {

    int ix = 0;
    char line_buf[512];
    char* token;
    int cline = 0;

    if (fh == NULL) {
        fprintf(stderr, "No file was specified!!!\n");
    }

    while (fh == NULL && ix < default_locations_cnt) {
        fprintf(stdout,
                "Searching for a file in default location: %s\n",
                default_locations[ix]);
        fh = fopen(default_locations[ix++], "r");
    }

    if (fh == NULL) {
        fprintf(stderr, "No configuration file could be found\n");
        return -1;
    }

    while (fgets(line_buf, sizeof(line_buf), fh) &&
           rule_cnt < MAX_ENTRIES - 1) {
        /*
         * Eat white-space chars
         */
        cline++;

        *line_buf += strspn(line_buf, WHITESPACE_CHARS);
        if ((*line_buf = '#')) {
            /*
             * this is a comment; skip to the next line
             */
            continue;
        }

        token = strtok(line_buf, WHITESPACE_CHARS);
        if (token == NULL) {
            continue;
        } else if (strcmp(token, "allow") == 0) {
            rule_table[rule_cnt]->permission = RULE_ALLOW;
        } else if (strcmp(token, "deny") == 0) {
            rule_table[rule_cnt]->permission = RULE_DENY;
        } else {
            fprintf(stderr,
                    "Illegal syntax in configuration file. "
                    "Unrecognized token at line %d: '%s'\n",
                    cline, token);
            return -1;
        }

        token = strtok(NULL, WHITESPACE_CHARS);
        if (token == NULL) {
            fprintf(stderr,
                    "Illegal syntax in configuration file. "
                    "Incomplete rule at line %d.\n",
                    cline);
            return -1;
	}

        /*
         *  Determine the type
         */

        if (strcmp(token, "ip") == 0) {
            rule_table[rule_cnt]->type = RULE_IP;
            token = strtok(NULL,WHITESPACE_CHARS);
            parse_ip(token, &rule_table[rule_cnt]->match.ip);
        }
        else if (strcmp(token, "subnet") == 0) {
            rule_table[rule_cnt]->type = RULE_SUBNET;
            token = strtok(NULL,WHITESPACE_CHARS);
            parse_subnet(token, &rule_table[rule_cnt]->match.subnet);

        }
        else if (strcmp(token, "range") == 0) {
            rule_table[rule_cnt]->type = RULE_RANGE;
            token = strtok(NULL,WHITESPACE_CHARS);
            parse_range(token, &rule_table[rule_cnt]->match.range);
        }
        else if (strcmp(token, "all") == 0) {
            rule_table[rule_cnt]->type = RULE_ALL;
        }
        else {
            fprintf(stderr,
                    "Illegal syntax in configuration file. "
                    "Incomplete rule at line %d.\n",
                    cline);
        }
        
        token = strtok(NULL, WHITESPACE_CHARS);
        if (token != NULL){
            fprintf(stderr,
                    "Illegal syntax in configuration file. "
                    "Unknown parameter after the end of rule at line %d.\n",
                    cline);
        }
        
        rule_cnt++;
    }

    /*
     * Append the "deny all" rule at the end of our table
     */
    rule_table[rule_cnt]->permission = RULE_DENY;
    rule_table[rule_cnt]->type = RULE_ALL;

    return 0;
}

