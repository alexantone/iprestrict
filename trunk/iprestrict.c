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
#include "parse.h"

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
