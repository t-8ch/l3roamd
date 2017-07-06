#include "clientmgr.h"
#include "routemgr.h"
#include "icmp6.h"
#include "timespec.h"
#include "error.h"
#include "l3roamd.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* Static functions used only in this file. */
static bool client_is_active(const struct client *client);
static void checkclient_task(void *d);
static void checkclient(clientmgr_ctx *ctx, uint8_t mac[6]);
static const char *state_str(enum ip_state state);

struct in6_addr mac2ipv6(uint8_t mac[6]) {
	struct in6_addr ipv6_address = {};
	inet_pton(AF_INET6, NODE_CLIENT_PREFIX, &ipv6_address);

	ipv6_address.s6_addr[8] = mac[0] ^ 0x02;
	ipv6_address.s6_addr[9] = mac[1];
	ipv6_address.s6_addr[10] = mac[2];
	ipv6_address.s6_addr[11] = 0xff;
	ipv6_address.s6_addr[12] = 0xfe;
	ipv6_address.s6_addr[13] = mac[3];
	ipv6_address.s6_addr[14] = mac[4];
	ipv6_address.s6_addr[15] = mac[5];

	return ipv6_address;
}
bool prefix_contains(const struct prefix *prefix, struct in6_addr *addr) {
	int plen = prefix->plen;

	for (int i = 0; i < 16; i++) {
		int mask = ~((1<<(8 - (plen > 8 ? 8 : plen))) - 1);

		if ((addr->s6_addr[i] & mask) != prefix->prefix.s6_addr[i])
			return false;

		plen -= 8;

		if (plen < 0)
			plen = 0;
	}
	return true;
}

void print_client(struct client *client) {
	char ifname[IFNAMSIZ];

	printf("Client %02x:%02x:%02x:%02x:%02x:%02x", client->mac[0], client->mac[1],
	                                               client->mac[2], client->mac[3],
	                                               client->mac[4], client->mac[5]);

	if (client_is_active(client))
		printf(" (active");
	else
		printf(" (______");

	if (client->ifindex != 0) {
		if_indextoname(client->ifindex, ifname);
		printf(", %s/%i)\n", ifname, client->ifindex);
	} else {
		printf(")\n");
	}

	for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
		struct client_ip *addr = &VECTOR_INDEX(client->addresses, i);

		char str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &addr->addr, str, INET6_ADDRSTRLEN);

		switch (addr->state) {
			case IP_INACTIVE:
				printf("  %s  %s\n", state_str(addr->state), str);
				break;
			case IP_ACTIVE:
				printf("  %s    %s (%ld.%.9ld)\n", state_str(addr->state), str, addr->timestamp.tv_sec, addr->timestamp.tv_nsec);
				break;
			case IP_TENTATIVE:
				printf("  %s %s (tries left: %d)\n", state_str(addr->state), str, addr->tentative_retries_left);
				break;
			default:
				exit_error("Invalid IP state");
		}
	}
}

/** Check whether a client is currently active.
    A client is considered active when at least one of its IP addresses is
    currently active or tentative.
    */
bool client_is_active(const struct client *client) {
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	if (timespec_cmp(client->active_until, now) > 0)
		return true;

	// TODO: how redundant ist client->active_until and the IP->state IP_ACTIVE?
	for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
		struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);

		if (ip->state == IP_ACTIVE || ip->state == IP_TENTATIVE)
			return true;
	}

	return false;
}

/** Adds the special node client IP address.
  */
void add_special_ip(clientmgr_ctx *ctx, struct client *client) {
	struct in6_addr address = mac2ipv6(client->mac);
	printf("Adding special address\n");
	rtnl_add_address(CTX(routemgr), &address);
}

/** Removes the special node client IP address.
  */
void remove_special_ip(clientmgr_ctx *ctx, struct client *client) {
	struct in6_addr address = mac2ipv6(client->mac);
	printf("Removing special address\n");
	rtnl_remove_address(CTX(routemgr), &address);
}

/** Given an IP address returns the IP object of a client.
    Returns NULL if no object is found.
    */
struct client_ip *get_client_ip(struct client *client, const struct in6_addr *address) {
	for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
		struct client_ip *e = &VECTOR_INDEX(client->addresses, i);

		if (memcmp(address, &e->addr, sizeof(struct in6_addr)) == 0)
			return e;
	}

	return NULL;
}

/** Removes an IP address from a client. Safe to call if the IP is not
    currently present in the clients list.
    */
void delete_client_ip(struct client *client, const struct in6_addr *address) {
	for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
		struct client_ip *e = &VECTOR_INDEX(client->addresses, i);

		if (memcmp(address, &e->addr, sizeof(struct in6_addr)) == 0) {
			VECTOR_DELETE(client->addresses, i);
			break;
		}
	}

	printf("\x1b[31mDeleting\x1b[0m ");
	print_client(client);
}

/** Adds a route.
  */
void client_add_route(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip) {
	if (clientmgr_is_ipv4(ctx, &ip->addr)) {
		struct in_addr ip4 = {
			.s_addr = ip->addr.s6_addr[12] << 24 | ip->addr.s6_addr[13] << 16 | ip->addr.s6_addr[14] << 8 | ip->addr.s6_addr[15]
		};

		routemgr_insert_route(CTX(routemgr), ctx->export_table, ctx->nat46ifindex, &ip->addr);
		routemgr_insert_route4(CTX(routemgr), ctx->export_table, client->ifindex, &ip4);
		routemgr_insert_neighbor4(CTX(routemgr), client->ifindex, &ip4, client->mac);
	} else {
		routemgr_insert_route(CTX(routemgr), ctx->export_table, client->ifindex, &ip->addr);
		routemgr_insert_neighbor(CTX(routemgr), client->ifindex, &ip->addr, client->mac);
	}
}

/** Remove a route.
  */
void client_remove_route(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip) {
	if (clientmgr_is_ipv4(ctx, &ip->addr)) {
		struct in_addr ip4 = {
			.s_addr = ip->addr.s6_addr[12] << 24 | ip->addr.s6_addr[13] << 16 | ip->addr.s6_addr[14] << 8 | ip->addr.s6_addr[15]
		};

		routemgr_remove_route(CTX(routemgr), ctx->export_table, &ip->addr);
		routemgr_remove_route4(CTX(routemgr), ctx->export_table, &ip4);
		routemgr_remove_neighbor4(CTX(routemgr), client->ifindex, &ip4, client->mac);
	} else {
		routemgr_remove_route(CTX(routemgr), ctx->export_table, &ip->addr);
		routemgr_remove_neighbor(CTX(routemgr), client->ifindex, &ip->addr, client->mac);
	}
}

/** Given a MAC address returns a client object.
    Returns NULL if the client is not known.
    */
struct client *get_client(clientmgr_ctx *ctx, const uint8_t mac[6]) {
	for (int i = 0; i < VECTOR_LEN(ctx->clients); i++) {
		struct client *e = &VECTOR_INDEX(ctx->clients, i);

		if (memcmp(mac, e->mac, sizeof(uint8_t) * 6) == 0)
			return e;
	}

	return NULL;
}

/** Get a client or create a new, empty one.
  */
struct client *get_or_create_client(clientmgr_ctx *ctx, const uint8_t mac[6]) {
	struct client *client = get_client(ctx, mac);

	if (client == NULL) {
		struct client _client = {};
		memcpy(_client.mac, mac, sizeof(uint8_t) * 6);
		VECTOR_ADD(ctx->clients, _client);
		client = &VECTOR_INDEX(ctx->clients, VECTOR_LEN(ctx->clients) - 1);
	}

	return client;
}

/** Given a MAC address deletes a client. Safe to call if the client is not
    known.
    */
void delete_client(clientmgr_ctx *ctx, const uint8_t mac[6]) {
	// TODO free addresses vector here?
	for (int i = 0; i < VECTOR_LEN(ctx->clients); i++) {
		struct client *client = &VECTOR_INDEX(ctx->clients, i);

		if (memcmp(mac, client->mac, sizeof(uint8_t) * 6) == 0) {
			VECTOR_FREE(client->addresses);
			VECTOR_DELETE(ctx->clients, i);
			break;
		}
	}
}

const char *state_str(enum ip_state state) {
	switch (state) {
		case IP_INACTIVE:
			return "\x1b[31mINACTIVE\x1b[0m";
		case IP_ACTIVE:
			return "\x1b[32mACTIVE\x1b[0m";
		case IP_TENTATIVE:
			return "\x1b[33mTENTATIVE\x1b[0m";
		default:
			return "\x1b[35m(INVALID)\x1b[0m";
	}
}

/** Change state of an IP address. Trigger all side effects like resetting
    counters, timestamps and route changes.
  */
void client_ipaddress_set_state(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip, enum ip_state state) {
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	switch (ip->state) {
		case IP_INACTIVE:
			switch (state) {
				case IP_INACTIVE:
					// ignore
					break;
				case IP_ACTIVE:
					client_add_route(ctx, client, ip);
					ip->timestamp = now;
					break;
				case IP_TENTATIVE:
					ip->timestamp = now;
					ip->tentative_retries_left = TENTATIVE_TRIES;
					break;
			}
			break;
		case IP_ACTIVE:
			switch (state) {
				case IP_INACTIVE:
					ip->timestamp = now;
					client_remove_route(ctx, client, ip);
					break;
				case IP_ACTIVE:
					ip->timestamp = now;
					// TODO update route
					break;
				case IP_TENTATIVE:
					ip->timestamp = now;
					ip->tentative_retries_left = TENTATIVE_TRIES;
					client_remove_route(ctx, client, ip);
					break;
			}
			break;
		case IP_TENTATIVE:
			switch (state) {
				case IP_INACTIVE:
					ip->timestamp = now;
					break;
				case IP_ACTIVE:
					ip->timestamp = now;
					client_add_route(ctx, client, ip);
					break;
				case IP_TENTATIVE:
					ip->timestamp = now;
					ip->tentative_retries_left = TENTATIVE_TRIES;
					break;
			}
			break;
	}

	char ip_str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &ip->addr, ip_str, INET6_ADDRSTRLEN);

	printf("%s changes from %s to %s\n", ip_str, state_str(ip->state),
	                                     state_str(state));

	ip->state = state;
}

/** Schedule a client check. Set timeout to 0 in order to check the client at
    the next iteration.
    */
void schedule_clientcheck(clientmgr_ctx *ctx, struct client *client, unsigned int timeout) {
	struct client_task *data = calloc(1, sizeof(struct client_task));

	data->ctx = ctx;
	memcpy(data->mac, client->mac, 6);

	if (!reschedule_task(CTX(taskqueue), client->check_task, timeout))
		client->check_task = post_task(CTX(taskqueue), timeout, checkclient_task, free, data);
}

/** Wrapper for checkclient to be used in post_task.
  */
void checkclient_task(void *d) {
	struct client_task *data = d;
	checkclient(data->ctx, data->mac);
}

/** Check a client.
  */
void checkclient(clientmgr_ctx *ctx, uint8_t mac[6]) {
	struct client *client = get_client(ctx, mac);

	// The client may have vanished.
	if (client == NULL)
		return;

	printf("Checking ");
	print_client(client);

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	struct timespec ipaddress_inactive_timeout = now;
	struct timespec client_timeout = now;

	ipaddress_inactive_timeout.tv_sec -= INACTIVE_TIMEOUT;
	client_timeout.tv_sec -= CLIENT_TIMEOUT;

	for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
		struct client_ip *addr = &VECTOR_INDEX(client->addresses, i);

		switch (addr->state) {
			case IP_ACTIVE:
				if (timespec_cmp(addr->timestamp, ipaddress_inactive_timeout) <= 0)
					client_ipaddress_set_state(ctx, client, addr, IP_INACTIVE);

				if (clientmgr_is_ipv4(ctx, &addr->addr))
					arp_send_request(CTX(arp), &addr->addr);
				else
					icmp6_send_solicitation(CTX(icmp6), &addr->addr);
				break;
			case IP_INACTIVE:
				if (timespec_cmp(addr->timestamp, client_timeout) <= 0) {
					VECTOR_DELETE(client->addresses, i);
					i--;
				}
				break;
			case IP_TENTATIVE:
				if (clientmgr_is_ipv4(ctx, &addr->addr))
					arp_send_request(CTX(arp), &addr->addr);
				else
					icmp6_send_solicitation(CTX(icmp6), &addr->addr);

				addr->tentative_retries_left--;
				if (addr->tentative_retries_left <= 0)
					client_ipaddress_set_state(ctx, client, addr, IP_INACTIVE);
				break;
		}
	}

	
	bool client_timeout_was_reached = (timespec_cmp(client->active_until, now) <= 0);
	bool client_has_no_ip_addresses = (VECTOR_LEN(client->addresses) == 0);
	
	if (client_has_no_ip_addresses && client_timeout_was_reached ) {
		delete_client(ctx, client->mac);
	} else {
		// TODO find the earliest timeout of all the ip addresses of the client and schedule the check then.
		schedule_clientcheck(ctx, client, IP_CHECKCLIENT_INTERVAL);
	}
}

/** Check whether an IP address is contained in a client prefix.
  */
bool clientmgr_valid_address(clientmgr_ctx *ctx, struct in6_addr *address) {
	return prefix_contains(&ctx->prefix, address) | clientmgr_is_ipv4(ctx, address);
}

/** Check whether an IP address is contained in the IPv4 prefix.
  */
bool clientmgr_is_ipv4(clientmgr_ctx *ctx, struct in6_addr *address) {
	return prefix_contains(&ctx->v4prefix, address);
}

/** Add a new address to a client identified by its MAC.
 */
void clientmgr_add_address(clientmgr_ctx *ctx, struct in6_addr *address, uint8_t *mac, unsigned int ifindex) {
	// TODO sicherstellen, dass IPs nur jeweils einem Client zugeordnet sind

	char str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, address, str, INET6_ADDRSTRLEN);
	printf("Add Address: %s (MAC %02x:%02x:%02x:%02x:%02x:%02x)\n", str, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	if (!clientmgr_valid_address(ctx, address))
		return;

	struct client *client = get_or_create_client(ctx, mac);
	struct client_ip *ip = get_client_ip(client, address);

	bool was_active = client_is_active(client);
	bool ip_is_new = ip == NULL;

	if (ip == NULL) {
		struct client_ip _ip = {};
		memcpy(&_ip.addr, address, sizeof(struct in6_addr));
		VECTOR_ADD(client->addresses, _ip);
		ip = &VECTOR_INDEX(client->addresses, VECTOR_LEN(client->addresses) - 1);
	}

	client->ifindex = ifindex;

	client_ipaddress_set_state(ctx, client, ip, IP_ACTIVE);

	if (!was_active) {
		struct in6_addr address = mac2ipv6(client->mac);
		if (!intercom_claim(CTX(intercom), &address, client))
			add_special_ip(ctx, client);
	}

	// If the IP address is new, add to distributed database (neighbor's for now).
	if (ip_is_new)
		intercom_info(CTX(intercom), NULL, client, false);

	schedule_clientcheck(ctx, client, IP_CHECKCLIENT_INTERVAL);
}

/** Notify the client manager about a new MAC (e.g. a new wifi client).
  */
void clientmgr_notify_mac(clientmgr_ctx *ctx, uint8_t *mac, unsigned int ifindex) {
	struct client *client = get_or_create_client(ctx, mac);

	char ifname[IFNAMSIZ];
	if_indextoname(ifindex, ifname);

	printf("\033[34mnew client %02x:%02x:%02x:%02x:%02x:%02x on %s\033[0m\n",
	       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ifname);

	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	client->active_until = now;
	client->active_until.tv_sec += CLIENT_TIMEOUT;
	client->ifindex = ifindex;

	struct in6_addr address = mac2ipv6(client->mac);
	if (!intercom_claim(CTX(intercom), &address, client)) {
		printf("Claim failed.\n");
		add_special_ip(ctx, client);
	}

	// Mark all inactive IP addresses tentative and schedule a check to establish
	// whether the client is using them now.
	for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
		struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);

		if (ip->state == IP_TENTATIVE || ip->state == IP_INACTIVE)
			client_ipaddress_set_state(ctx, client, ip, IP_TENTATIVE);
	}

	schedule_clientcheck(ctx, client, 0);
}

/** Handle info request.
  */
void clientmgr_handle_claim(clientmgr_ctx *ctx, const struct in6_addr *sender, uint8_t mac[6]) {
	struct client *client = get_client(ctx, mac);

	if (client == NULL)
		return;

	bool active = client_is_active(client);

	if (active)
		remove_special_ip(ctx, client);

	intercom_info(CTX(intercom), sender, client, active);

	if (!client_is_active(client))
		return;

	printf("Dropping client in response to claim\n");

	for (int i = 0; i < VECTOR_LEN(client->addresses); i++) {
		struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);

		if (ip->state == IP_ACTIVE || ip->state == IP_TENTATIVE)
			client_ipaddress_set_state(ctx, client, ip, IP_TENTATIVE);
	}

	schedule_clientcheck(ctx, client, 0);
}

/** Handle incoming client info.
  */
void clientmgr_handle_info(clientmgr_ctx *ctx, struct client *foreign_client, bool relinquished) {
	struct client *client = get_client(ctx, foreign_client->mac);

	if (client == NULL || !client_is_active(client))
		return;

	for (int i = 0; i < VECTOR_LEN(foreign_client->addresses); i++) {
		struct client_ip *foreign_ip = &VECTOR_INDEX(foreign_client->addresses, i);
		struct client_ip *ip = get_client_ip(client, &foreign_ip->addr);

		// Skip if we know this IP address
		if (ip != NULL)
			continue;

		VECTOR_ADD(client->addresses, *foreign_ip);
		ip = &VECTOR_INDEX(client->addresses, VECTOR_LEN(client->addresses) - 1);

		client_ipaddress_set_state(ctx, client, ip, IP_TENTATIVE);
	}

	if (relinquished)
		add_special_ip(ctx, client);

	printf("Merged ");
	print_client(client);

	schedule_clientcheck(ctx, client, 0);
}

