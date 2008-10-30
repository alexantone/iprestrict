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


#define WHITESPACE_CHARS " \t"

#define BASE10 10
#define BASE16 16

extern int parse_ip(const char * const token, ipr_ip_t * const out);
extern int parse_range(const char * const token, ipr_range_t * const out);
extern int parse_subnet(const char* const token, ipr_subnet_t * const out);
extern int parse_file (FILE *fh);

#endif /* PARSE_H_ */
