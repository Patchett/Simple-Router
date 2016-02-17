#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"

/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend a request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr)
{
    struct sr_arpreq *request = (&(sr->cache))->requests;
    struct sr_arpreq *next_request;
    while (request) {
        next_request = request->next;
        handle_arpreq(sr, request);
        request = next_request;
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpentry *entry = NULL, *copy = NULL;

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }

    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }

    pthread_mutex_unlock(&(cache->lock));

    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.

   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }

    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }

    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));

        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
        new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req, *prev = NULL, *next = NULL;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            if (prev) {
                next = req->next;
                prev->next = next;
            } else {
                next = req->next;
                cache->requests = next;
            }

            break;
        }
        prev = req;
    }

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid)) {
            break;
        }
    }

    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry)
{
    pthread_mutex_lock(&(cache->lock));

    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL;
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } else {
                    next = req->next;
                    cache->requests = next;
                }

                break;
            }
            prev = req;
        }

        struct sr_packet *pkt, *nxt;

        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf) {
                free(pkt->buf);
            }
            if (pkt->iface) {
                free(pkt->iface);
            }
            free(pkt);
        }

        free(entry);
    }

    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache)
{
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }

    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache)
{
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));

    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache)
{
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr)
{
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);

    while (1) {
        sleep(1.0);

        pthread_mutex_lock(&(cache->lock));

        time_t curtime = time(NULL);

        int i;
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime, cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }

        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }

    return NULL;
}

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *request)
{
    if (difftime(time(NULL), request->sent) >= 1.0) {
        if (request->times_sent >= 5) {
            /* We have tried this ARP request 5 times. Send icmp3 */
            fprintf(stderr, "ARP request timed out. Sending ICMP3.\n");
            struct sr_packet *waiting_packet = request->packets;
            while (waiting_packet) {
                /* Get the interface that the packet came in on. We will send the ICMP back the way the original packet came. */
                uint8_t *icmp_packet_outgoing_interface_eth_address = (extract_ethernet_header(waiting_packet->buf))->ether_dhost;
                struct sr_if *outgoing_interface = get_interface_from_eth(sr, icmp_packet_outgoing_interface_eth_address);
                if (NULL == outgoing_interface) {
                    fprintf(stderr, "Error: Ethernet address in original packet did not match an interface on this router.\n");
                    waiting_packet = waiting_packet->next;
                    continue;
                }
                send_custom_icmp_packet(sr, waiting_packet->buf, waiting_packet->len, outgoing_interface->name, 3, 1, NULL);
                waiting_packet = waiting_packet->next;
            }
            sr_arpreq_destroy(&(sr->cache), request);
            return;
        }
        struct sr_if *interface = sr_get_interface(sr, request->packets->iface);
        fprintf(stderr, "Sending ARP request...\n");
        int arp_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        uint8_t *new_arp_request_packet = (uint8_t *) malloc(arp_packet_len);
        memset(new_arp_request_packet, 0, sizeof(uint8_t) * arp_packet_len);
        sr_ethernet_hdr_t *outgoing_ethernet_header = extract_ethernet_header(new_arp_request_packet);
        sr_arp_hdr_t *outgoing_arp_header = extract_arp_header(new_arp_request_packet);
        /* Prepare ethernet header */
        memcpy(outgoing_ethernet_header->ether_shost, interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
        memset(outgoing_ethernet_header->ether_dhost, 0xff, sizeof(uint8_t) * ETHER_ADDR_LEN); /* Broadcast */
        outgoing_ethernet_header->ether_type = htons(ethertype_arp);
        /* Prepare ARP header*/
        outgoing_arp_header->ar_op = htons(arp_op_request);
        memset(outgoing_arp_header->ar_tha, 0xff, ETHER_ADDR_LEN); /* Broadcast */
        memcpy(outgoing_arp_header->ar_sha, interface->addr, ETHER_ADDR_LEN);
        outgoing_arp_header->ar_pln = sizeof(uint32_t);
        outgoing_arp_header->ar_hln = ETHER_ADDR_LEN;
        outgoing_arp_header->ar_pro = htons(ethertype_ip);
        outgoing_arp_header->ar_hrd = htons(arp_hrd_ethernet);
        outgoing_arp_header->ar_tip = request->ip;
        outgoing_arp_header->ar_sip = interface->ip;
        request->sent = time(NULL);
        request->times_sent++;
        sr_send_packet(sr, new_arp_request_packet, arp_packet_len, interface->name);
        free(new_arp_request_packet);
    }
    return;
}

