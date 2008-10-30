/*
 * check_functions.c
 *
 *  Created on: Oct 24, 2008
 *      Author: sorin
 */

/*
 *  Ip check function
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iprestrict.h"

int ip_check(char* token, int cline, int rule_cnt) {

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

int range_check(char* token, int cline, int rule_cnt) {

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

int mask_check(char* token, int cline, int rule_cnt) {

	char* word;
	int ix=0;

	word = strtok(token,".");
	for (ix=0; ix<4; ix++) {

		if ((strlen(word) != 3) || (atoi(word) == 0 ) || (atoi(word) > 255 ) || (word == NULL) ) {
			fprintf(stderr, "The ip found at line %d is invalid", cline);
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
