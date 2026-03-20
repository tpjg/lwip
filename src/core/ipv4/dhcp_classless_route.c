/**
 * @file
 * DHCP Option 121 (Classless Static Routes) Parser - RFC 3442
 *
 * Parses classless static routes from DHCP responses and populates
 * the IPv4 static route table.
 */

/*
 * Copyright (c) 2026 Timo Gatsonides
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * Author: Timo Gatsonides
 */

#include "lwip/opt.h"

#if LWIP_DHCP_CLASSLESS_STATIC_ROUTES

#include "lwip/dhcp_classless_route.h"
#include "lwip/ip4_route_table.h"
#include "lwip/prot/dhcp.h"
#include "lwip/sys.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/def.h"

#include <string.h>

/* Per-interface tracking of whether Option 121 was received */
static u8_t option121_received[LWIP_DHCP_CLASSLESS_ROUTE_MAX_NETIFS];

/* Lock for thread-safe access to option121_received state */
static sys_lock_t option121_lock;

/* Get a safe index for the option121_received array, returns -1 if out of bounds */
static inline int
get_netif_idx(struct netif *netif)
{
  u8_t idx;
  if (netif == NULL)
    return -1;
  idx = netif_get_index(netif);
  if (idx == 0 || idx > LWIP_DHCP_CLASSLESS_ROUTE_MAX_NETIFS)
    return -1;
  return idx - 1;
}

/* Calculate significant octets for a prefix length: ceil(prefix_len / 8) */
static inline u8_t
prefix_to_octets(u8_t prefix_len)
{
  return (prefix_len + 7) / 8;
}

void
dhcp_classless_route_init(void)
{
  SYS_ARCH_LOCK_INIT(&option121_lock);
  memset(option121_received, 0, sizeof(option121_received));
}

int
dhcp_parse_classless_routes(struct netif *netif, struct pbuf *p,
                            u16_t offset, u8_t len)
{
  int routes_parsed = 0;
  u16_t pos = offset;
  u16_t end;
  int netif_idx;

  if (netif == NULL || p == NULL)
    return ERR_ARG;  /* ERR_ARG is already negative */

  netif_idx = get_netif_idx(netif);
  if (netif_idx < 0)
    return ERR_ARG;

  /* overflow check */
  if (offset > 0xFFFF - len)
    return ERR_ARG;
  end = offset + len;

  /* empty option is valid but contains no routes */
  if (len == 0)
    return 0;

  /*
   * Clear any existing DHCP routes for this interface first.
   * This ensures we replace old routes with new ones on lease renewal.
   */
  ip4_route_remove_dhcp(netif);

  /*
   * Parse each route entry in the option.
   * Format per RFC 3442:
   *   1 byte:  prefix length (0-32)
   *   N bytes: significant octets of destination (N = ceil(prefix_len/8))
   *   4 bytes: gateway IP address
   */
  while (pos < end) {
    u8_t prefix_len;
    u8_t significant_octets;
    ip4_addr_t dest;
    ip4_addr_t gateway;
    u8_t dest_bytes[4] = {0, 0, 0, 0};

    /* read prefix length */
    if (pbuf_copy_partial(p, &prefix_len, 1, pos) != 1)
      break;
    pos++;

    if (prefix_len > 32)
      break;

    significant_octets = prefix_to_octets(prefix_len);

    /* check we have enough data remaining */
    if (pos + significant_octets + 4 > end)
      break;

    /* read destination network (significant octets only) */
    if (significant_octets > 0) {
      if (pbuf_copy_partial(p, dest_bytes, significant_octets, pos)
              != significant_octets)
        break;
    }
    pos += significant_octets;

    /*
     * Reconstruct destination address.
     * The significant octets are the high-order bytes of the address.
     * dest_bytes is already zero-initialized for non-significant octets.
     */
    dest.addr = (dest_bytes[0] << 24) | (dest_bytes[1] << 16) |
                (dest_bytes[2] << 8) | dest_bytes[3];
    dest.addr = lwip_htonl(dest.addr);

    /* apply mask to ensure destination is properly masked (RFC 3442) */
    dest.addr &= ip4_prefix_to_mask(prefix_len);

    /* read gateway address - already in network byte order */
    if (pbuf_copy_partial(p, &gateway.addr, 4, pos) != 4)
      break;
    pos += 4;

    /*
     * Validate gateway address:
     * - Reject multicast/broadcast (invalid as next-hop)
     * - 0.0.0.0 is valid per RFC 3442: means destination is on-link
     *   (directly reachable on this interface without a gateway)
     */
    if (ip4_addr_ismulticast(&gateway) ||
        ip4_addr_isbroadcast(&gateway, netif))
      continue;

    /* add route to table */
    if (ip4_route_add(&dest, prefix_len, &gateway, netif,
                      IP4_ROUTE_FLAG_DHCP) == ERR_OK) {
      routes_parsed++;
    }
  }

  /*
   * Mark that this interface received Option 121.
   * This is used to determine whether to ignore Option 3 (Router).
   */
  if (routes_parsed > 0) {
    SYS_ARCH_LOCK(&option121_lock);
    option121_received[netif_idx] = 1;
    SYS_ARCH_UNLOCK(&option121_lock);
  }

  return routes_parsed;
}

u8_t
dhcp_classless_route_received(struct netif *netif)
{
  u8_t result = 0;
  int netif_idx = get_netif_idx(netif);

  if (netif_idx < 0)
    return 0;

  SYS_ARCH_LOCK(&option121_lock);
  result = (option121_received[netif_idx] != 0);
  SYS_ARCH_UNLOCK(&option121_lock);

  return result;
}

void
dhcp_classless_route_clear(struct netif *netif)
{
  int netif_idx = get_netif_idx(netif);

  if (netif_idx < 0)
    return;

  SYS_ARCH_LOCK(&option121_lock);
  option121_received[netif_idx] = 0;
  SYS_ARCH_UNLOCK(&option121_lock);

  ip4_route_remove_dhcp(netif);
}

#endif /* LWIP_DHCP_CLASSLESS_STATIC_ROUTES */
