/*
 * --------------------------------------------------------------------
 * parse.c
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

int parse_ip (const char * const token, ipr_ip_t * const out) {

    int ix = 0;
    unsigned long temp_byte;
    char * cursor = token;

    memset(out, 0, sizeof(out));

    while (ix < 4) {
        temp_byte = strtoul(cursor, &cursor, BASE10);

        if (temp_byte > 255) {
            return -1;
        }

        if (*cursor != '.' && ix < 3) {
            return -2;
        }

        if (ix < 3) {
            cursor++;
        }
        
        out->ip_dd[ix] = temp_byte;
        ix++;
    }

    if (*cursor != '\0') {
        return -3;
    }

    return 0;
}

/*
 * Range check function
 */

int parse_range (const char * const token, ipr_range_t * const out) {

    int ix = 0;
    unsigned long temp_byte;
    char * cursor = token;

    memset(out, 0, sizeof(out));

    /*
     * Parse the first ip.
     */
    while (ix < 4) {
        temp_byte = strtoul(cursor, &cursor, BASE10);

        if (temp_byte > 255) {
            return -1;
        }

        if (*cursor != '.' && ix < 3) {
            return -2;
        }

        if (ix < 3) {
            cursor++;
        }

        out->start.ip_dd[ix] = temp_byte;
        ix++;
    }
    
    if (*cursor != '-') {
        return -3;
    }
    cursor++;
    /*
     * Parse the second ip.
     */
    ix = 0;
    while (ix < 4) {
        temp_byte = strtoul(cursor, &cursor, BASE10);

        if (temp_byte > 255) {
            return -1;
        }

        if (*cursor != '.' && ix < 3) {
            return -2;
        }

        if (ix < 3) {
            cursor++;
        }

        out->stop.ip_dd[ix] = temp_byte;
        ix++;
    }

    if (*cursor != '\0') {
        return -3;
    }

    return 0;
}

/*
 *  Mask check function
 */

int parse_subnet (const char* const token, ipr_subnet_t * const out) {

    int ix = 0;
    unsigned long temp_byte;
    unsigned long temp_mask;
    char * cursor = token;

    memset(out, 0, sizeof(out));

    /*
     * Parse the subnet.
     */
    while (ix < 4) {
        temp_byte = strtoul(cursor, &cursor, BASE10);

        if (temp_byte > 255) {
            return -1;
        }

        if (*cursor != '.' && ix < 3) {
            return -2;
        }

        if (ix < 3) {
            cursor++;
        }

        out->ip.ip_dd[ix] = temp_byte;
        ix++;
    }
    
    if (*cursor != '/') {
        return -3;
    }

    cursor++;
    temp_mask = strtoul(cursor, &cursor, BASE10);
    if (temp_mask > MAX_MASK_BYTES) {
        return -4;
    }
    
    out->mask = temp_mask;
    
    return 0;

}


