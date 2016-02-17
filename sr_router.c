/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * Ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet/* lent */,
                     unsigned int len,
                     char *interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n", len);

    /* fill in code here */

    if (ethertype_ip == ethertype(packet)) {
        handle_ip_packet(sr, packet, len, interface);
    } else if (ethertype_arp == ethertype(packet)) {
        handle_arp_packet(sr, packet, len, interface);
    }
}/* end sr_ForwardPacket */


void handle_ip_packet(struct sr_instance *sr,
                      uint8_t *packet/* lent */,
                      unsigned int len,
                      char *interface/* lent */)
{
    if (sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) > len) {
        fprintf(stderr, "Error! Cannot process IP packet because it was not long enough.\n");
        return;
    }
    sr_ip_hdr_t *original_ip_header = extract_ip_header(packet);
    sr_icmp_hdr_t *original_icmp_header = extract_icmp_header(packet);
    /* Check IP Header cksum */
    uint16_t original_sum = original_ip_header->ip_sum;
    original_ip_header->ip_sum = 0;
    original_ip_header->ip_sum = cksum(original_ip_header, sizeof(sr_ip_hdr_t));
    if (original_ip_header->ip_sum != original_sum) {
        fprintf(stderr, "IP Header chksum failed\n");
        original_ip_header->ip_sum = original_sum;
        return;
    }
    /* Check if packet is destined for one of my interfaces */
    struct sr_if *destination_interface = get_interface_from_ip(sr, original_ip_header->ip_dst);
    if (destination_interface) {
        if (ip_protocol_icmp == original_ip_header->ip_p) {
            if (sizeof(sr_icmp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) > len) {
                fprintf(stderr, "Error! Cannot process ICMP packet because it was not long enough.\n");
                return;
            }
            /* Packet is for one of my interfaces and is ICMP */
            fprintf(stderr, "%s received a packet destined for it.\n", interface);
            original_sum = original_icmp_header->icmp_sum;
            original_icmp_header->icmp_sum = 0;
            original_icmp_header->icmp_sum = cksum(original_icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
            if (original_icmp_header->icmp_sum != original_sum) {
                fprintf(stderr, "ICMP Header chksum failed\n");
                original_icmp_header->icmp_sum = original_sum;
                return;
            }
            if (original_icmp_header->icmp_type != 8) {
                fprintf(stderr, "Packet is not an echo request\n");
                return;
            }
            fprintf(stderr, "Packet received by %s was an echo request. Sending back echo reply.\n", interface);
            send_custom_icmp_packet(sr, packet, len, interface, 0x00, 0x00, destination_interface);
            return;
        } else {  /*Packet is not ICMP.*/
            send_custom_icmp_packet(sr, packet, len, interface, 3, 3, destination_interface);
            return;
        }
    } else {  /* Packet was not for one of my interfaces */
        fprintf(stderr, "Received packet on interface %s that was not for me\n", interface);
        if (1 >= original_ip_header->ip_ttl) {
            fprintf(stderr, "The ttl has expired. Sending icmp11\n");
            send_custom_icmp_packet(sr, packet, len, interface, 11, 0, NULL);
            return;
        }
        /* Packet is not for this router and has valid TTL. Forward the packet. */
        fprintf(stderr, "Forwarding packet that was received on interface %s\n", interface);
        struct sr_rt *next_hop_ip = calculate_LPM(sr, original_ip_header->ip_dst);
        if (!next_hop_ip) { /* No match found in routing table */
            fprintf(stderr, "LPM was unable to find a match in the routing table. Sending ICMP3\n");
            send_custom_icmp_packet(sr, packet, len, interface, 3, 0, NULL);
            return;
        }
        original_ip_header->ip_ttl--;
        original_ip_header->ip_sum = 0;
        original_ip_header->ip_sum = cksum(original_ip_header, sizeof(sr_ip_hdr_t));
        struct sr_arpentry *next_hop_mac = sr_arpcache_lookup(&(sr->cache), next_hop_ip->gw.s_addr);
        if (!next_hop_mac) { /* No ARP cache entry found */
            fprintf(stderr, "No ARP cache entry was found. Queuing an ARP request\n");
            struct sr_arpreq *queued_arp_req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip->gw.s_addr /*original_ip_header->ip_dst*/,
                                               packet, len, next_hop_ip->interface);
            handle_arpreq(sr, queued_arp_req);
            return;
        }
        fprintf(stderr, "ARP cache entry was found. Putting the packet on interface %s toward next hop.\n", next_hop_ip->interface);
        sr_ethernet_hdr_t *send_ethernet_header = extract_ethernet_header(packet);
        memcpy(send_ethernet_header->ether_shost, sr_get_interface(sr, next_hop_ip->interface)->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
        memcpy(send_ethernet_header->ether_dhost, next_hop_mac->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
        free(next_hop_mac);
        sr_send_packet(sr, packet, len, sr_get_interface(sr, next_hop_ip->interface)->name);
        return;
    }
}

void send_custom_icmp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                             char *receiving_interface, uint8_t icmp_type, uint8_t icmp_code, struct sr_if *destination_interface)
{
    int header_len = sizeof(sr_icmp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    int outgoing_len;
    if (0x00 == icmp_type) { /* Send back original data with headers if type 0 */
        outgoing_len = len;
    } else { /* Send back only headers if not type 0 */
        outgoing_len = header_len;
    }
    uint8_t *send_icmp_packet = (uint8_t *)malloc(outgoing_len);
    memset(send_icmp_packet, 0, sizeof(uint8_t) * outgoing_len);
    sr_ethernet_hdr_t *original_ethernet_header = extract_ethernet_header(packet);
    sr_ip_hdr_t *original_ip_header = extract_ip_header(packet);
    sr_icmp_hdr_t *send_icmp_header = extract_icmp_header(send_icmp_packet);
    sr_ip_hdr_t *send_ip_header = extract_ip_header(send_icmp_packet);
    sr_ethernet_hdr_t *send_ethernet_header = extract_ethernet_header(send_icmp_packet);
    struct sr_if *outgoing_interface = sr_get_interface(sr, receiving_interface);
    uint32_t source_ip = outgoing_interface->ip;
    if (destination_interface) { /* Check if the packet was destined for an interface other than the one it came in on */
        source_ip = destination_interface->ip;
    }
    /*Prepare ICMP Header*/
    if (0x00 == icmp_type) {
        /* Copying ICMP metadata into new ICMP header for type 0 */
        fprintf(stderr, "Outgoing ICMP is type 0. Copying original ICMP header into outgoing ICMP header\n");
        memcpy(send_icmp_header, extract_icmp_header(packet), outgoing_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    } else {
        /*Copying 28 bytes of IP Header into icmp header for type 11 or type 3*/
        memcpy(send_icmp_header->data, original_ip_header, ICMP_DATA_SIZE);
    }
    send_icmp_header->icmp_code = icmp_code;
    send_icmp_header->icmp_type = icmp_type;
    send_icmp_header->icmp_sum = 0;
    if (0x00 == icmp_type) { /* Calculate cksum for header + data if type 0 */
        send_icmp_header->icmp_sum = cksum(send_icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    } else { /* Calculate cksum for header only if not type 0 */
        send_icmp_header->icmp_sum = cksum(send_icmp_header, sizeof(sr_icmp_hdr_t));
    }
    /*Prepare IP Header*/
    memcpy(send_ip_header, original_ip_header, sizeof(sr_ip_hdr_t));
    send_ip_header->ip_ttl = INIT_TTL;
    send_ip_header->ip_p = ip_protocol_icmp;
    send_ip_header->ip_dst = original_ip_header->ip_src;
    send_ip_header->ip_len = htons(outgoing_len - sizeof(sr_ethernet_hdr_t));
    send_ip_header->ip_src = source_ip;
    send_ip_header->ip_sum = 0;
    send_ip_header->ip_sum = cksum(send_ip_header, sizeof(sr_ip_hdr_t));
    /*Prepare Ethernet Header*/
    memcpy(send_ethernet_header->ether_shost, outgoing_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(send_ethernet_header->ether_dhost, original_ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    send_ethernet_header->ether_type = htons(ethertype_ip);
    sr_send_packet(sr, send_icmp_packet, outgoing_len, receiving_interface);
    free(send_icmp_packet);
    return;
}

void handle_arp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
    if (sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t) > len) {
        fprintf(stderr, "Error! Cannot process ARP packet because it was not long enough.\n");
        return;
    }
    sr_arp_hdr_t *original_arp_header = extract_arp_header(packet);
    sr_ethernet_hdr_t *original_ethernet_header = extract_ethernet_header(packet);
    struct sr_if *receiving_interface = sr_get_interface(sr, interface);
    if (arp_op_request == ntohs(original_arp_header->ar_op)) { /* ARP Request */
        /* Check if the request is for this interface */
        if (original_arp_header->ar_tip != receiving_interface->ip) {
            return;
        }
        fprintf(stderr, "Received ARP request on interface %s\n", interface);
        uint8_t *arp_reply = (uint8_t *) malloc(len);
        memset(arp_reply, 0, len * sizeof(uint8_t));
        sr_ethernet_hdr_t *reply_ethernet_header = extract_ethernet_header(arp_reply);
        sr_arp_hdr_t *reply_arp_header = extract_arp_header(arp_reply);
        /* Prepare ethernet header */
        memcpy(reply_ethernet_header->ether_shost, receiving_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
        memcpy(reply_ethernet_header->ether_dhost, original_ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
        reply_ethernet_header->ether_type = htons(ethertype_arp);
        /* Prepare ARP header*/
        memcpy(reply_arp_header, original_arp_header, sizeof(sr_arp_hdr_t));
        reply_arp_header->ar_op = htons(arp_op_reply);
        memcpy(reply_arp_header->ar_tha, original_ethernet_header->ether_shost, ETHER_ADDR_LEN);
        memcpy(reply_arp_header->ar_sha, receiving_interface->addr, ETHER_ADDR_LEN);
        reply_arp_header->ar_tip = original_arp_header->ar_sip;
        reply_arp_header->ar_sip = receiving_interface->ip;
        sr_send_packet(sr, arp_reply, len, interface);
        free(arp_reply);
    } else if (arp_op_reply == ntohs(original_arp_header->ar_op)) { /* ARP Reply */
        fprintf(stderr, "Received ARP reply on interface %s\n", interface);

        struct sr_arpreq *cached_arp_request = sr_arpcache_insert(&(sr->cache),
                                               original_arp_header->ar_sha,
                                               original_arp_header->ar_sip);
        if (cached_arp_request) {
            fprintf(stderr, "Sending packets that were waiting on ARP reply...\n");
            struct sr_packet *waiting_packet = cached_arp_request->packets;
            while (waiting_packet) { /* Send all packets waiting on this ARP request*/
                uint8_t *send_packet = waiting_packet->buf;
                sr_ethernet_hdr_t *send_ethernet_header = extract_ethernet_header(send_packet);
                memcpy(send_ethernet_header->ether_dhost, original_arp_header->ar_sha, ETHER_ADDR_LEN);
                memcpy(send_ethernet_header->ether_shost, receiving_interface->addr, ETHER_ADDR_LEN);
                sr_send_packet(sr, send_packet, waiting_packet->len, interface);
                waiting_packet = waiting_packet->next;
            }
            sr_arpreq_destroy(&(sr->cache), cached_arp_request);
        }
    }
    return;
}

struct sr_rt *calculate_LPM(struct sr_instance *sr, uint32_t destination_ip)
{
    struct sr_rt *routing_table_node = sr->routing_table;
    struct sr_rt *best_match = NULL;
    while (routing_table_node) {
        if ((routing_table_node->dest.s_addr & routing_table_node->mask.s_addr) == (destination_ip & routing_table_node->mask.s_addr)) {
            if (!best_match || (routing_table_node->mask.s_addr > best_match->mask.s_addr)) {
                best_match = routing_table_node;
            }
        }
        routing_table_node = routing_table_node->next;
    }
    return best_match;
}
