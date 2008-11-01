/*
 * -----------------------------------------------
 * parse.h
 *
 *  Created on: Oct 30, 2008
 *      Author: sorin
 * -----------------------------------------------
 */

#ifndef PARSE_H_
#define PARSE_H_

static const char *default_locations[] = {
        "/etc/iprestrict.cfg",
        "iprestrict.cfg" };

static const int default_locations_cnt = sizeof(default_locations)
        / sizeof(default_locations[0]);

#define WHITESPACE_CHARS " \t\n\r"

#define BASE10 10
#define BASE16 16


extern int parse_args (const int argc, char * const argv[],
                       FILE ** p_fh, char ** p_ifdev);

extern int parse_range(const char * const token, ipr_range_t * const out);
extern int parse_subnet(const char* const token, ipr_subnet_t * const out);
extern int parse_file(FILE ** p_fh);

#endif /* PARSE_H_ */
