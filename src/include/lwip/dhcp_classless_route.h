/**
 * @file
 * DHCP Option 121 (Classless Static Routes) Parser - RFC 3442
 *
 * Parses DHCP Option 121 responses and populates the IPv4 static route
 * table with classless static routes provided by the DHCP server.
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

#ifndef LWIP_HDR_DHCP_CLASSLESS_ROUTE_H
#define LWIP_HDR_DHCP_CLASSLESS_ROUTE_H

#include "lwip/opt.h"

#if LWIP_DHCP_CLASSLESS_STATIC_ROUTES

#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Initialize the Option 121 module - must be called before other functions */
void dhcp_classless_route_init(void);

/**
 * Parse DHCP Option 121 data and add routes to the static route table.
 *
 * Parses variable-length encoding per RFC 3442:
 *   1 byte:  prefix length (0-32)
 *   N bytes: significant octets of destination (N = ceil(prefix_len/8))
 *   4 bytes: gateway IP address
 *
 * Routes are added with IP4_ROUTE_FLAG_DHCP flag. Existing DHCP routes
 * for the interface are cleared first.
 *
 * @param netif network interface that received the DHCP response
 * @param p pbuf containing the option data
 * @param offset offset into pbuf where option data starts
 * @param len length of option data
 * @return number of routes successfully added (>= 0), or negative error
 */
int dhcp_parse_classless_routes(struct netif *netif, struct pbuf *p,
                                u16_t offset, u8_t len);

/**
 * Check if Option 121 was received for an interface.
 * Per RFC 3442, if Option 121 is present, Option 3 (Router) must be ignored.
 *
 * @param netif network interface to check
 * @return 1 if Option 121 was received, 0 otherwise
 */
u8_t dhcp_classless_route_received(struct netif *netif);

/**
 * Clear Option 121 state and routes for a network interface.
 * Called when DHCP lease is released, interface is removed, etc.
 *
 * @param netif network interface to clear
 */
void dhcp_classless_route_clear(struct netif *netif);

#ifdef __cplusplus
}
#endif

#endif /* LWIP_DHCP_CLASSLESS_STATIC_ROUTES */

#endif /* LWIP_HDR_DHCP_CLASSLESS_ROUTE_H */
