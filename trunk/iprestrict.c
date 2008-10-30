/*
 * ---------------------------------------------------------------
 * iprestrict.c
 *
 *  Created on: Oct 24, 2008
 *      Author: sorin
 * ---------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "iprestrict.h"
#include "check_functions.c"

static FILE *fh = NULL;
static char *ifdev = NULL;

int parse_args (const int argc,char * const argv[]) {

	int ix;

	for (ix = 1; ix < argc; ) {

		if (strcmp(argv[ix], "-f") == 0 && fh == NULL) {
			/*
			 * Parse the filename
			 */
			ix++;

			fh = fopen(argv[ix], "r" );

			if (fh == NULL) {
				fprintf(stderr, "File %s could not be opened!!!\n", argv[ix] );
				return -1;
			}
			ix++;
		}
		else if (strcmp(argv[ix], "-i") == 0 && ifdev == NULL) {
			/*
			 * Parse the interface
			 */
			ix++;
			ifdev = argv[ix];
			ix++;

		}
		else {
			fprintf(stderr, "Unknown or duplicate argument:%s\n", argv[ix]);
			return -1;
		}
	}
	return 0;
}

#define WHITESPACE_CHARS " \t"

int parse_file(FILE *fh) {

	int 	ix = 0;
	char 	line_buf[512];
	char* 	token;
	int 	cline = 0;


	if (fh == NULL) {
		fprintf(stderr, "No file was specified!!!\n" );
	}

	while (fh == NULL && ix < default_locations_cnt ) {
		fprintf("Searching for a file in default location: %s\n", default_locations[ix]);
		fh = fopen(default_locations[ix++], "r");
	}

	if (fh == NULL) {
		fprintf(stderr, "No configuration file could be found\n" );
		return -1;
	}

	while (fgets(line_buf, sizeof(line_buf), fh)) {
		/*
		 * Eat white-space chars
		 */
		cline++;

		*line_buf += strspn(line_buf, WHITESPACE_CHARS);
		if ((*line_buf = '#')){
			/*
			 * this is a comment; skip to the next line
			 */
			continue;
		}

		token = strtok(line_buf, WHITESPACE_CHARS);
		if (token == NULL) {
			continue;
		}
		else if (strcmp(token, "allow") == 0) {
			rule_table[rule_cnt]->permission = RULE_ALLOW;
		}
		else if (strcmp(token, "deny") == 0) {
			rule_table[rule_cnt]->permission = RULE_DENY;
		}
		else {
			fprintf(stderr,
					"Illegal syntax in config file. Unrecognized token at line %d: '%s'\n",
					cline, token);
			return -1;
		}

		token = strtok(NULL, WHITESPACE_CHARS);
		if (token == NULL) {
			fprintf(stderr,
					"Illegal syntax in config file. Incomplete rule at line %d.\n",	cline);
			return -1;
		}

		/*
		 *  Determine the type
		 */

		if (strcmp(token, "ip") == 0) {
			rule_table[rule_cnt]->type = RULE_IP;
			token = strtok(NULL,WHITESPACE_CHARS);
			ip_check(token, cline, rule_cnt);
		}
		else if (strcmp(token, "mask") == 0) {
			rule_table[rule_cnt]->type = RULE_SUBNET;
			token = strtok(NULL,WHITESPACE_CHARS);
			mask_check(token, cline, rule_cnt);

		}
		else if (strcmp(token, "range") == 0) {
			rule_table[rule_cnt]->type = RULE_RANGE;
			token = strtok(NULL,WHITESPACE_CHARS);
			range_check(token, cline, rule_cnt);

		}
		else if (strcmp(token, "all") == 0) {
			rule_table[rule_cnt]->type = RULE_ALL;
		}
		else {
			fprintf(stderr,"Illegal syntax in config file. Incomplete rule at line %d.\n",	cline);
		}


		int cbyte = 0;
		int tmp_byte = 0;



//		while ((tmp_byte = stroul( token, &token, 10)) < 0xFF && (cbyte < 4)) {
//			rule_table[rule_cnt]->match.ip.
//		}

	}

	/*
	 * Append the "deny all" rule at the end of our table
	 */
	rule_table[rule_cnt]->permission = RULE_DENY;
	rule_table[rule_cnt]->type = RULE_ALL;

	return 0;
}

int main (int argc, char *argv[]){

	memset(rule_table, MAX_ENTRIES, sizeof(ipr_rule_t) );
	rule_cnt = 0;

	if (!parse_args(argc, argv)) {
		fclose(fh);
		exit(1);
	}

	if (!parse_file(fh)) {
		fclose(fh);
		exit(1);
	}

	return 0;
}
