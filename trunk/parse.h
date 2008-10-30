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

extern int parse_ip (char* token, int cline, int rule_cnt);
extern int parse_range (char* token, int cline, int rule_cnt);
extern int parse_subnet (char* token, int cline, int rule_cnt);

#endif /* PARSE_H_ */
