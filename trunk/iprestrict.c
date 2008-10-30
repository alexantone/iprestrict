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

static FILE *fh = NULL;
static char *ifdev = NULL;

static ipr_rule_t* rule_table[MAX_ENTRIES];
static int rule_cnt = 0;

static const char *default_locations[] = {
        "/etc/iprestrict.cfg",
        "iprestrict.cfg" };

static const int default_locations_cnt = sizeof(default_locations)
        / sizeof(default_locations[0]);

int parse_args (const int argc, char * const argv[]) {

    int ix = 1;

    while (ix < argc) {

        if (strcmp(argv[ix], "-f") == 0 && fh == NULL) {
            /*
             * Parse the filename
             */
            ix++;

            fh = fopen(argv[ix], "r");

            if (fh == NULL) {
                fprintf(stderr,
                "File %s could not be opened!!!\n", argv[ix]);
                return -1;
            }
            ix++;
        } else if (strcmp(argv[ix], "-i") == 0 && ifdev == NULL) {
            /*
             * Parse the interface
             */
            ix++;
            ifdev = argv[ix];
            ix++;

        } else {
            fprintf(stderr,
            "Unknown or duplicate argument:%s\n", argv[ix]);
            return -1;
        }
    }
    return 0;
}

int parse_file(void) {

    int ix = 0;
    char line_buf[512];
    char *token = NULL;
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
        rule_table[rule_cnt] = malloc(sizeof(ipr_rule_t));
        if (rule_table[rule_cnt] == NULL) {
            fprintf(stderr,"Could not allocate memory.");
            return -1;
        }

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

int main (int argc, char *argv[]) {

    memset(rule_table, MAX_ENTRIES, sizeof(ipr_rule_t));
    rule_cnt = 0;
    int exit_code = 0;

    if (parse_args(argc, argv) !=  0) {
        exit_code = -1;
        goto cleanup;
    }

    if (parse_file() != 0) {
        exit_code = -1;
        goto cleanup;
    }

    fprintf(stdout,
            "  ... Parsing of file was scucessuful. "
            "Number of rules in effect: %d\n",
            rule_cnt + 1);

cleanup:
    do_cleanup();

    return exit_code;
}
