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

#include <arpa/inet.h>

#include "iprestrict.h"
#include "parse.h"

int parse_args (const int argc, char * const argv[],
                FILE ** p_fh, char ** p_ifdev)
{


    int ix = 1;
    FILE * fh = NULL;
    char * ifdev = NULL;

    if (p_fh == NULL || p_ifdev == NULL) {
        return -1;
    }
    fh = *p_fh;
    ifdev = *p_ifdev;

    while (ix < argc) {

        if (strcmp(argv[ix], "-f") == 0 && fh == NULL) {
            /*
             * Parse the filename
             */
            ix++;

            fh = fopen(argv[ix], "r");

            if (fh == NULL) {
                fprintf(stderr,
                "File %s could not be opened!\n", argv[ix]);
                return -1;
            }
            ix++;
        } else if (strcmp(argv[ix], "-i") == 0 && ifdev == NULL) {
            /*
             * Parse the interface
             */
            ix++;
            strcpy(ifdev, argv[ix]);
            ix++;

        } else {
            fprintf(stderr,
            "Unknown or duplicate argument:%s\n", argv[ix]);
            return -1;
        }
    }
    return 0;
}


static int parse_ip (const char * const token, ipr_ip_t * const out)
{

    int ix = 0;
    unsigned long temp_byte;
    char * cursor = token;

    memset(out, 0, sizeof(out));

    while (ix < 4) {
        temp_byte = strtoul(cursor, &cursor, BASE10);

        if (temp_byte > 255) {
            return -1;
        }

        if (ix < 3 && *cursor != '.') {
            return -2;
        }

        if (ix < 3) {
            cursor++;
        }

        out->ip_dd[ix] = temp_byte;
        ix++;
    }

    if (*cursor != '\0') {
        return -3;
    }

    return 0;
}

/*
 * Range check function
 */

static int parse_range (const char * const token, ipr_range_t * const out)
{

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
        ix++;
    }

    if (*cursor != '-') {
        return -3;
    }
    cursor++;
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
        ix++;
    }

    if (*cursor != '\0') {
        return -3;
    }

    return 0;
}

/*
 *  Mask check function
 */

static int parse_subnet (const char* const token, ipr_subnet_t * const out)
{

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
        ix++;
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

int parse_file(FILE ** p_fh)
{

    int ix = 0;
    char line_buf[512];
    char *cursor;
    char *token = NULL;
    int cline = 0;
    FILE * fh = NULL;

    if (p_fh == NULL) {
        return -1;
    }
    fh = *p_fh;

    if (fh == NULL) {
        fprintf(stderr, "No configuration file was specified.\n");
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
        cursor = line_buf;

        cursor += strspn(cursor, WHITESPACE_CHARS);
        if (*cursor == '#') {
            /*
             * this is a comment; skip to the next line
             */
            continue;
        }

        token = strtok(cursor, WHITESPACE_CHARS);
        if (token == NULL) {
            continue;
        }

        rule_table[rule_cnt] = malloc(sizeof(ipr_rule_t));
        if (rule_table[rule_cnt] == NULL) {
            fprintf(stderr,"Could not allocate memory.");
            return -1;
        }

        if (strcmp(token, "allow") == 0) {
            rule_table[rule_cnt]->permission = RULE_ALLOW;
        } else if (strcmp(token, "deny") == 0) {
            rule_table[rule_cnt]->permission = RULE_DENY;
        } else {
            fprintf(stderr,
                    "Syntax error at line %d: '%s'\n",
                    cline, token);
            return -1;
        }

        token = strtok(NULL, WHITESPACE_CHARS);
        if (token == NULL) {
            fprintf(stderr,
                    "Syntax error at line %d: more arguments needed.\n",
                    cline);
            return -1;
        }

        /*
         *  Determine the type
         */

        if (strcmp(token, "ip") == 0) {
            rule_table[rule_cnt]->type = RULE_IP;
            token = strtok(NULL,WHITESPACE_CHARS);
            if (parse_ip(token, &rule_table[rule_cnt]->match.ip) != 0) {
                fprintf(stderr,
                        "Syntax error at line %d: '%s'\n",
                        cline, token);
                return -2;
            }
        }
        else if (strcmp(token, "subnet") == 0) {
            rule_table[rule_cnt]->type = RULE_SUBNET;
            token = strtok(NULL,WHITESPACE_CHARS);
            if (parse_subnet(token, &rule_table[rule_cnt]->match.subnet) != 0) {
                fprintf(stderr,
                        "Syntax error at line %d: '%s'\n",
                        cline, token);
                return -2;
            }
        }
        else if (strcmp(token, "range") == 0) {
            rule_table[rule_cnt]->type = RULE_RANGE;
            token = strtok(NULL,WHITESPACE_CHARS);
            if (parse_range(token, &rule_table[rule_cnt]->match.range) != 0) {
                fprintf(stderr,
                        "Syntax error at line %d: '%s'\n",
                        cline, token);
                return -2;
            }
            /*
             * We use htonl() to avoid any endianness problems
             * by forcing a BigEndian comparisson.
             */
            if (htonl(rule_table[rule_cnt]->match.range.start.ip_v) >
                htonl(rule_table[rule_cnt]->match.range.stop.ip_v)) {
                fprintf(stderr,
                        "Syntax error at line %d: '%s'\n",
                        cline, token);
                return -2;
            }
        }
        else if (strcmp(token, "all") == 0) {
            rule_table[rule_cnt]->type = RULE_ALL;
        }
        else {
            fprintf(stderr,
                    "Syntax error at line %d: more arguments needed.\n",
                    cline);
            return -2;
        }

        token = strtok(NULL, WHITESPACE_CHARS);
        if (token != NULL){
            fprintf(stderr,
                    "Illegal syntax in configuration file. "
                    "Unknown parameter after the end of rule at line %d.\n",
                    cline);
            return -2;
        }

        rule_cnt++;
    }

    /*
     * Append the "deny all" rule at the end of our table
     */
    rule_table[rule_cnt] = malloc(sizeof(ipr_rule_t));
    if (rule_table[rule_cnt] == NULL) {
        fprintf(stderr,"Could not allocate memory.");
        return -1;
    }
    rule_table[rule_cnt]->permission = RULE_DENY;
    rule_table[rule_cnt]->type = RULE_ALL;

    if (fh != NULL) {
        fclose(fh);
    }

    return 0;
}

