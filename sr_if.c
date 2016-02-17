/*-----------------------------------------------------------------------------
 * file:  sr_inface.
 * date:  Sun Oct 06 14:13:13 PDT 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * Data structures and methods for handling interfaces
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#ifdef _DARWIN_
    #include <sys/types.h>
#endif /* _DARWIN_ */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sr_if.h"
#include "sr_router.h"

/*---------------------------------------------------------------------
 * Method: sr_get_interface
 * Scope: Global
 *
 * Given an interface name return the interface record or 0 if it doesn't
 * exist.
 *
 *---------------------------------------------------------------------*/

struct sr_if *sr_get_interface(struct sr_instance *sr, const char *name)
{
    struct sr_if *if_walker = 0;

    /* -- REQUIRES -- */
    assert(name);
    assert(sr);

    if_walker = sr->if_list;

    while (if_walker) {
        if (!strncmp(if_walker->name, name, sr_IFACE_NAMELEN))
        { return if_walker; }
        if_walker = if_walker->next;
    }

    return 0;
} /* -- sr_get_interface -- */

/*---------------------------------------------------------------------
 * Method: sr_add_interface(..)
 * Scope: Global
 *
 * Add and interface to the router's list
 *
 *---------------------------------------------------------------------*/

void sr_add_interface(struct sr_instance *sr, const char *name)
{
    struct sr_if *if_walker = 0;

    /* -- REQUIRES -- */
    assert(name);
    assert(sr);

    /* -- empty list special case -- */
    if (sr->if_list == 0) {
        sr->if_list = (struct sr_if *)malloc(sizeof(struct sr_if));
        assert(sr->if_list);
        sr->if_list->next = 0;
        strncpy(sr->if_list->name, name, sr_IFACE_NAMELEN);
        return;
    }

    /* -- find the end of the list -- */
    if_walker = sr->if_list;
    while (if_walker->next)
    {if_walker = if_walker->next; }

    if_walker->next = (struct sr_if *)malloc(sizeof(struct sr_if));
    assert(if_walker->next);
    if_walker = if_walker->next;
    strncpy(if_walker->name, name, sr_IFACE_NAMELEN);
    if_walker->next = 0;
} /* -- sr_add_interface -- */

/*---------------------------------------------------------------------
 * Method: sr_sat_ether_addr(..)
 * Scope: Global
 *
 * set the ethernet address of the LAST interface in the interface list
 *
 *---------------------------------------------------------------------*/

void sr_set_ether_addr(struct sr_instance *sr, const unsigned char *addr)
{
    struct sr_if *if_walker = 0;

    /* -- REQUIRES -- */
    assert(sr->if_list);

    if_walker = sr->if_list;
    while (if_walker->next)
    {if_walker = if_walker->next; }

    /* -- copy address -- */
    memcpy(if_walker->addr, addr, 6);

} /* -- sr_set_ether_addr -- */

/*---------------------------------------------------------------------
 * Method: sr_set_ether_ip(..)
 * Scope: Global
 *
 * set the IP address of the LAST interface in the interface list
 *
 *---------------------------------------------------------------------*/

void sr_set_ether_ip(struct sr_instance *sr, uint32_t ip_nbo)
{
    struct sr_if *if_walker = 0;

    /* -- REQUIRES -- */
    assert(sr->if_list);

    if_walker = sr->if_list;
    while (if_walker->next)
    {if_walker = if_walker->next; }

    /* -- copy address -- */
    if_walker->ip = ip_nbo;

} /* -- sr_set_ether_ip -- */

/*---------------------------------------------------------------------
 * Method: sr_print_if_list(..)
 * Scope: Global
 *
 * print out the list of interfaces to stdout
 *
 *---------------------------------------------------------------------*/

void sr_print_if_list(struct sr_instance *sr)
{
    struct sr_if *if_walker = 0;

    if (sr->if_list == 0) {
        printf(" Interface list empty \n");
        return;
    }

    if_walker = sr->if_list;

    sr_print_if(if_walker);
    while (if_walker->next) {
        if_walker = if_walker->next;
        sr_print_if(if_walker);
    }

} /* -- sr_print_if_list -- */

/*---------------------------------------------------------------------
 * Method: sr_print_if(..)
 * Scope: Global
 *
 * print out a single interface to stdout
 *
 *---------------------------------------------------------------------*/

void sr_print_if(struct sr_if *iface)
{
    struct in_addr ip_addr;

    /* -- REQUIRES --*/
    assert(iface);
    assert(iface->name);

    ip_addr.s_addr = iface->ip;

    Debug("%s\tHWaddr", iface->name);
    DebugMAC(iface->addr);
    Debug("\n");
    Debug("\tinet addr %s\n", inet_ntoa(ip_addr));
} /* -- sr_print_if -- */

struct sr_if *get_interface_from_ip(struct sr_instance *sr, uint32_t ip_address)
{
    struct sr_if *current_interface = sr->if_list;
    struct sr_if *destination_interface = NULL;
    while (current_interface) {
        if (ip_address == current_interface->ip) { /* left, none */
            destination_interface = current_interface;
            break;
        }
        current_interface = current_interface->next;
    }
    return destination_interface;
}

struct sr_if *get_interface_from_eth(struct sr_instance *sr, uint8_t *eth_address)
{
    struct sr_if *current_interface = sr->if_list;
    struct sr_if *destination_interface = NULL;
    short match_found, i;
    while (current_interface) {
        match_found = 1;
        for (i = 0; i < ETHER_ADDR_LEN; i++) {
            if (current_interface->addr[i] != eth_address[i]) {
                match_found = 0;
                break;
            }
        }
        if (match_found) {
            fprintf(stderr, "get_interface_from_eth found a matching interface.\n");
            destination_interface = current_interface;
            break;
        }
        current_interface = current_interface->next;
    }
    return destination_interface;
}
