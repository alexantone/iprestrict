/*
 * ------------------------------------------------------------------------
 * subinterface.h
 *
 *  Created on: Oct 31, 2008
 *      Author: alex
 * ------------------------------------------------------------------------
 */

#ifndef SUBINTERFACE_H_
#define SUBINTERFACE_H_

/*
 * Device subinterfaces structures
 */

#define MAX_SUBINTERFACES 256

typedef struct {
    unsigned char inuse;
    ipr_ip_t      ip;
    unsigned int  ttl;      // how many packets will this subinterface be taken
} dev_sif_t;

extern dev_sif_t subif_table[];

#endif /* SUBINTERFACE_H_ */
