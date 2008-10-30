/*
 *----------------------------------------------------------
 * parse.c
 *
 *  Created on: Oct 24, 2008
 *      Author: sorin
 * ---------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iprestrict.h"
#include "parse.h"

int parse_ip (char* token, int cline, int rule_cnt) {

	char* word;
	int ix=0;
	word = strtok(token,".");

	for (ix=0; ix<4; ix++) {

		if ((strlen(word) != 3) || (atoi(word) == 0 ) || (atoi(word) > 255 ) || (word == NULL) ) {
			fprintf(stderr, "The ip found at line %d is invalid", cline);
			return -1;
		}

		strcpy(rule_table[rule_cnt]->match.ip.ip_dd[ix], word);
		word = strtok(NULL,".");
	}


	return 0;
}

/*
 * Range check function
 */

int parse_range (char* token, int cline, int rule_cnt) {

	char* word;
	int ix=0;
	word = strtok(token,".");

	for (ix=0; ix<8; ix++) {

		if ((strlen(word) != 3) || (atoi(word) == 0 ) || (atoi(word) > 255 ) || (word == NULL) ) {
			fprintf(stderr, "The ip range found at line %d is invalid", cline);
			return -1;
		}
		if ( ix<4 ) {
			strcpy(rule_table[rule_cnt]->match.range.start.ip_dd[ix], word);
		} else {
			strcpy(rule_table[rule_cnt]->match.range.stop.ip_dd[ix], word);
		}
		word = strtok(NULL,".-");

	}
	if (rule_table[rule_cnt]->match.range.start.ip_v >= rule_table[rule_cnt]->match.range.stop.ip_v) {
		fprintf(stderr, "The ip range found at line %d is invalid", cline);
		return -1;
	}
	return 0;

}


/*
 *  Mask check function
 */

int parse_subnet (const char* const token, ipr_fmt_subnet_t* out) {

	char* word;
	int ix=0;

	word = strtok(token,".");
	for (ix=0; ix<4; ix++) {

		if ((strlen(word) != 3) || (atoi(word) == 0 ) || (atoi(word) > 255 ) || (word == NULL) ) {
			return -1;
		}

		strcpy(rule_table[rule_cnt]->match.subnet.ip.ip_dd[ix], word);
		word = strtok(NULL,"./");
	}

	if ((atoi(word) > 0) && (atoi(word) < 25)){
		rule_table[rule_cnt]->match.subnet.mask = atoi(word);
	}

	return 0;

}


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
					"Illegal syntax in configuration file. Unrecognized token at line %d: '%s'\n",
					cline, token);
			return -1;
		}

		token = strtok(NULL, WHITESPACE_CHARS);
		if (token == NULL) {
			fprintf(stderr,
					"Illegal syntax in configuration file. Incomplete rule at line %d.\n",	cline);
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
			parse_subnet(token, cline, rule_cnt);

		}
		else if (strcmp(token, "range") == 0) {
			rule_table[rule_cnt]->type = RULE_RANGE;
			token = strtok(NULL,WHITESPACE_CHARS);
			parse_range(token, cline, rule_cnt);

		}
		else if (strcmp(token, "all") == 0) {
			rule_table[rule_cnt]->type = RULE_ALL;
		}
		else {
			fprintf(stderr,"Illegal syntax in configuration file. Incomplete rule at line %d.\n",	cline);
		}
	}

	/*
	 * Append the "deny all" rule at the end of our table
	 */
	rule_table[rule_cnt]->permission = RULE_DENY;
	rule_table[rule_cnt]->type = RULE_ALL;

	return 0;
}

