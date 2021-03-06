/*
  Copyright (c) 2015, Nils Schneider <nils@nilsschneider.net>
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#pragma once

#include "vector.h"
#include "taskqueue.h"

#include <stdint.h>
#include <netinet/in.h>

#define IPCHECK_INTERVAL 2
#define PACKET_TIMEOUT 2
#define SEEK_TIMEOUT 10

struct packet {
	struct timespec timestamp;
	ssize_t len;
	uint8_t *data;
};

struct entry {
	struct in6_addr address;
	struct timespec timestamp;
	taskqueue_t *check_task;
	VECTOR(struct packet*) packets;
};

typedef struct {
	int fd;
	char *ifname;
	struct l3ctx *l3ctx;
	VECTOR(struct entry) addrs;
	VECTOR(struct packet) output_queue;
} ipmgr_ctx;

struct ip_task {
	ipmgr_ctx *ctx;
	struct in6_addr address;
};

void ipmgr_init(ipmgr_ctx *ctx, char *tun_name, unsigned int mtu);
void ipmgr_route_appeared(ipmgr_ctx *ctx, const struct in6_addr *destination);
void ipmgr_handle_in(ipmgr_ctx *ctx, int fd);
void ipmgr_handle_out(ipmgr_ctx *ctx, int fd);
