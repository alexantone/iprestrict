/*
 * ------------------------------------------------------------------------
 * subinterface.h
 *
 *  Created on: Oct 31, 2008
 *      Author: alex
 * ------------------------------------------------------------------------
 */

#include "iprestrict.h"

#ifndef SUBINTERFACE_H_
#define SUBINTERFACE_H_

extern void block_ip(ipr_ip_t ip);

extern void if_up(const char * const interface,
           const unsigned int subinterface,
           const ipr_ip_t ip);

extern void if_down(const char * const interface,
             const unsigned int subinterface);


#endif /* SUBINTERFACE_H_ */
