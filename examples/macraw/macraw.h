/**
 * Copyright (c) 2021 WIZnet Co.,Ltd
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _MACRAW_H_
#define _MACRAW_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include "wizchip_conf.h"
#include "socket.h"

/* MACRAW test debug message printout enable */
#define	_MACRAW_DEBUG_

/* DATA_BUF_SIZE define for MACRAW example */
#ifndef MACRAW_DATA_BUF_SIZE
	#define MACRAW_DATA_BUF_SIZE			2048
#endif

/************************/
/* Select MACRAW_MODE */
/************************/
#define MACRAW_MAIN_NOBLOCK    0
#define MACRAW_MODE   MACRAW_MAIN_NOBLOCK

typedef struct {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
} __attribute__ ((packed)) ethernet_header;

typedef struct {
    uint8_t ihl_version;	// version 4bit header length 4bit
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t frag_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
} __attribute__ ((packed)) ip_header;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__ ((packed)) udp_header;

typedef struct {
	ethernet_header raw_eth_header;
	ip_header raw_ip_header;
	udp_header raw_udp_header;
} __attribute__ ((packed)) packet_macraw;

typedef struct {
	uint8_t src_ip[4];
	uint8_t dst_ip[4];
	uint8_t zero;
	uint8_t protocol;
	uint16_t udp_length;
} __attribute__ ((packed)) pseudo_header;

/* MACRAW example */
int32_t macraw(uint8_t sn, uint8_t* buf);
bool packet_parser(wiz_NetInfo net_info, packet_macraw* pk, uint8_t* buf);
bool src_mac_match(uint8_t* mac, uint8_t* buf);
bool dst_mac_match(uint8_t* mac, uint8_t* buf);
bool src_ip_match(uint8_t* ip, uint8_t* buf);
bool dst_ip_match(uint8_t* ip, uint8_t* buf);
int32_t get_ip_version(uint8_t* buf);
void get_mac(uint8_t* src_mac, uint8_t* dst_mac, uint8_t* buf);
void get_ip(uint8_t* src_ip, uint8_t* dst_ip, uint8_t* buf);
uint8_t get_ip_header_len(uint8_t* buf);
uint8_t get_protocol(uint8_t* buf);
void copy_swap(uint8_t* src, uint8_t* dst, uint32_t len);
#if 0
uint16_t checksum(packet_macraw* buf, uint8_t* data, uint16_t len);\
uint32_t calculate_checksum(uint16_t* buf, uint32_t size);
#endif

#ifdef __cplusplus
}
#endif

#endif
