/**
 * Copyright (c) 2021 WIZnet Co.,Ltd
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * ----------------------------------------------------------------------------------------------------
 * Includes
 * ----------------------------------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include "macraw.h"

int32_t macraw(uint8_t sn, uint8_t* buf)
{
  int32_t  ret;
  uint16_t size, sentsize;
  uint8_t  destip[4];
  uint16_t destport;
  uint16_t port = 5000;
  uint8_t count=0;
  uint8_t head[2];
  uint16_t pack_len = 0;
  
  switch(getSn_SR(sn))
  {
    case SOCK_MACRAW :
      if((pack_len = getSn_RX_RSR(sn)) > 0)
      {
        if(pack_len > MACRAW_DATA_BUF_SIZE)
        {
          pack_len = MACRAW_DATA_BUF_SIZE;
        }
        //printf("pack_len = %d\r\n", pack_len);

#if 1
        wiz_recv_data(sn, head, 2);
        setSn_CR(sn, Sn_CR_RECV);

        // byte size of data packet (2byte)
        pack_len = head[0];
        pack_len = (pack_len << 8) + head[1];
        pack_len -= 2;

        #if 0
        printf("pack_len = %d\r\n", pack_len);
        #endif
#if 0
        if (pack_len > len)
        {
            // Packet is bigger than buffer - drop the packet
            wiz_recv_ignore(sn, pack_len);
            setSn_CR(sn, Sn_CR_RECV);
            return 0;
        }
#endif
        wiz_recv_data(sn, buf, pack_len); // data copy
        setSn_CR(sn, Sn_CR_RECV);
        return pack_len;
#else
        
        ret = recvfrom(sn, buf, size, destip, (uint16_t*)&destport, 4);
        if(ret < 0)
        {
          printf("failed ret = %d\r\n", ret);
        }
        else
        {
          printf("recv ret = %d\r\n", ret);
          return ret;
        }
#endif
      }
    break;
      
    case SOCK_CLOSED:
      ret = socket(sn, Sn_MR_MACRAW, port, 0x00);
      printf("ret = %d\r\n", ret);
      return ret;
    break;
      
    default :
    break;
  }
  return 0;
}

bool src_mac_match(uint8_t* mac, uint8_t* buf)
{
  // 678 91011
}

bool dst_mac_match(uint8_t* mac, uint8_t* buf)
{
  // 012 345
}

bool src_ip_match(uint8_t* ip, uint8_t* buf)
{
  int32_t i;
  int32_t ip_type;
  bool ret;

  ip_type = get_ip_version(buf);

  if(ip_type == 4)
  {
    // src IP
    // 30 31 32 33

    for(i=0; i<4; i++)
    {
      #if 1
      // 20230818 taylor
      printf("ip %d buf %d\r\n", ip[i], buf[30+i]);
      #endif
      
      if(ip[i] != buf[30+i])
      {
        ret = false;
        break;
      }
      else
      {
        ret = true;
      }
    }
  }
  else if(ip_type == 6)
  {
    ret = false;
  }
  else
  {
    ret = false;
  }

  return ret;
}

bool dst_ip_match(uint8_t* ip, uint8_t* buf)
{
  int32_t i;
  int32_t ip_type;
  uint8_t src_ip[4];
  uint8_t dst_ip[4];
  bool ret;

  ip_type = get_ip_version(buf);

  if(ip_type == 4)
  {
    // dst IP
    // 26 27 28 29

    get_ip(src_ip, dst_ip, buf);

    for(i=0; i<4; i++)
    {
      #if 0
      // 20230818 taylor
      printf("ip %d dst_ip %d\r\n", ip[i], dst_ip[i]);
      #endif

      if(ip[i] != dst_ip[i])
      {
        ret = false;
        break;
      }
      else
      {
        ret = true;
      }
    }

    // src IP
    // 30 31 32 33
  }
  else if(ip_type == 6)
  {
    ret = false;
  }
  else
  {
    ret = false;
  }

  return ret;
}

int32_t get_ip_version(uint8_t* buf)
{
  int32_t ip_type;

  ip_type = 0;

  // IP Type 12 13

  // IPv4
  // 0x08 0x00
  if(buf[12] == 0x08 && buf[13] == 0x00)
  {
    ip_type = 4;
  }
  
  // IPv6
  //0x86 0xDD
  if(buf[12] == 0x86 && buf[13] == 0xDD)
  {
    ip_type = 6;
  }

  return ip_type;
}

void get_mac(uint8_t* src_mac, uint8_t* dst_mac, uint8_t* buf)
{
  int32_t i;

  for(i=0; i<6; i++)
  {
    src_mac[i] = buf[6+i];
    dst_mac[i] = buf[0+i];
  }
}

void get_ip(uint8_t* src_ip, uint8_t* dst_ip, uint8_t* buf)
{
  int32_t i;

  for(i=0; i<4; i++)
  {
    src_ip[i] = buf[26+i];
    dst_ip[i] = buf[30+i];
  }
#if 0
  for(i=0; i<4; i++)
  {
    printf("src_ip[%d]= %d buf[%d]= %d\r\n", i, src_ip[i], i, buf[26+i]);
  }

  for(i=0; i<4; i++)
  {
    printf("dst_ip[%d]= %d buf[%d]= %d\r\n", i, dst_ip[i], i, buf[30+i]);
  }
  printf("\r\n");
#endif
}

uint8_t get_ip_header_len(uint8_t* buf)
{
  return (buf[0]&0xf);
}

uint8_t get_protocol(uint8_t* buf)
{
  return buf[8];
}

bool packet_parser(wiz_NetInfo net_info, packet_macraw* pk, uint8_t* buf)
{
  uint32_t nextp;
  uint8_t ip_hlen;
  uint16_t data_len;
  uint16_t i;
  
  nextp = 0;

  // ethernet header
  memcpy(pk->raw_eth_header.dst_mac, buf, 6);
  nextp += 6;

  if((pk->raw_eth_header.dst_mac[0] != net_info.mac[0]) ||
  (pk->raw_eth_header.dst_mac[1] != net_info.mac[1]) ||
  (pk->raw_eth_header.dst_mac[2] != net_info.mac[2]) ||
  (pk->raw_eth_header.dst_mac[3] != net_info.mac[3]) ||
  (pk->raw_eth_header.dst_mac[4] != net_info.mac[4]) ||
  (pk->raw_eth_header.dst_mac[5] != net_info.mac[5]))
  {
    return false;
  }

  memcpy(pk->raw_eth_header.src_mac, buf+nextp, 6);
  nextp += 6;

  copy_swap(buf+nextp,(uint8_t*)&(pk->raw_eth_header.eth_type), 2);
  nextp += 2;

  if(pk->raw_eth_header.eth_type != 0x0800)
  {
    //printf("Not IPv4\r\n");
    return false;
  }

  // ip header
  pk->raw_ip_header.ihl_version = buf[nextp];
  nextp += 1;

  ip_hlen = (pk->raw_ip_header.ihl_version)&0xf;

  pk->raw_ip_header.tos = buf[nextp];
  nextp += 1;

  copy_swap(buf+nextp,(uint8_t*)&(pk->raw_ip_header.total_length), 2);
  nextp += 2;

  copy_swap(buf+nextp,(uint8_t*)&(pk->raw_ip_header.id), 2);
  nextp += 2;

  copy_swap(buf+nextp,(uint8_t*)&(pk->raw_ip_header.frag_offset), 2);
  nextp += 2;

  pk->raw_ip_header.ttl = buf[nextp];
  nextp += 1;

  pk->raw_ip_header.protocol = buf[nextp];
  nextp += 1;

  copy_swap(buf+nextp,(uint8_t*)&(pk->raw_ip_header.checksum), 2);
  nextp += 2;

  memcpy(pk->raw_ip_header.src_ip, buf+nextp, 4);
  nextp += 4;

  memcpy(pk->raw_ip_header.dst_ip, buf+nextp, 4);
  nextp += 4;
  
  if(ip_hlen > 20)
  {
    //printf("IP header > 20\r\n");
    return false;
  }

  if(pk->raw_ip_header.protocol != 17)
  {
    //printf("Not UDP\r\n");
    return false;
  }

  // udp header
  copy_swap(buf+nextp,(uint8_t*)&(pk->raw_udp_header.src_port), 2);
  nextp += 2;

  copy_swap(buf+nextp,(uint8_t*)&(pk->raw_udp_header.dst_port), 2);
  nextp += 2;

  copy_swap(buf+nextp,(uint8_t*)&(pk->raw_udp_header.length), 2);
  nextp += 2;

  copy_swap(buf+nextp,(uint8_t*)&(pk->raw_udp_header.checksum), 2);
  nextp += 2;

  printf("dst : %02x:%02x:%02x:%02x:%02x:%02x\r\n", 
    pk->raw_eth_header.dst_mac[0],
    pk->raw_eth_header.dst_mac[1],
    pk->raw_eth_header.dst_mac[2],
    pk->raw_eth_header.dst_mac[3],
    pk->raw_eth_header.dst_mac[4],
    pk->raw_eth_header.dst_mac[5]
    );

  printf("src : %02x:%02x:%02x:%02x:%02x:%02x\r\n", 
  pk->raw_eth_header.src_mac[0],
  pk->raw_eth_header.src_mac[1],
  pk->raw_eth_header.src_mac[2],
  pk->raw_eth_header.src_mac[3],
  pk->raw_eth_header.src_mac[4],
  pk->raw_eth_header.src_mac[5]
  );

  printf("dst ip : %d.%d.%d.%d\r\n", 
  pk->raw_ip_header.dst_ip[0],
  pk->raw_ip_header.dst_ip[1],
  pk->raw_ip_header.dst_ip[2],
  pk->raw_ip_header.dst_ip[3]
  );

  printf("src ip : %d.%d.%d.%d\r\n", 
  pk->raw_ip_header.src_ip[0],
  pk->raw_ip_header.src_ip[1],
  pk->raw_ip_header.src_ip[2],
  pk->raw_ip_header.src_ip[3]
  );

  data_len = (pk->raw_udp_header.length) - 8;
  printf("data_len = %d\r\n", data_len);
  
  printf("data(hex) : ");
  for(i=0; i<data_len; i++)
  {
    printf("%02x ", buf[nextp+i]);
  }
  printf("\r\ndata(char) : ");
  for(i=0; i<data_len; i++)
  {
    printf("%c", buf[nextp+i]);
  }
  printf("\r\n\r\n");

#if 1
  // 20231020 taylor
  uint16_t csum_temp;
  csum_temp = checksum(pk, &buf[nextp], data_len);
  if(pk->raw_udp_header.checksum != csum_temp)
  {
    printf("Checksum incorrect\r\n");
  }
  else
  {
    printf("Checksum correct\r\n");
  }
  printf("Recevied Checksum = 0x%.4x\r\n", pk->raw_udp_header.checksum);
  printf("Calculated Checksum = 0x%.4x\r\n\r\n", csum_temp);
#endif
}

void copy_swap(uint8_t* src, uint8_t* dst, uint32_t len)
{
  uint32_t i,j;

  for(i=0, j=len-1; i<len; i++, j--)
  {
    dst[j] = src[i];
    #if 0
    printf("dst[%d] %02x src[%d] %02x\r\n", j, dst[j], i, src[i]);
    #endif
  }
  #if 0
  printf("\r\n");
  #endif
}

#if 1

uint16_t checksum(packet_macraw* buf, uint8_t* data, uint16_t len)
{
  uint32_t sum = 0;
  uint32_t total_length = buf->raw_udp_header.length;

  pseudo_header psh;
  psh.src_ip[0] = buf->raw_ip_header.src_ip[0];
  psh.src_ip[1] = buf->raw_ip_header.src_ip[1];
  psh.src_ip[2] = buf->raw_ip_header.src_ip[2];
  psh.src_ip[3] = buf->raw_ip_header.src_ip[3];

  psh.dst_ip[0] = buf->raw_ip_header.dst_ip[0];
  psh.dst_ip[1] = buf->raw_ip_header.dst_ip[1];
  psh.dst_ip[2] = buf->raw_ip_header.dst_ip[2];
  psh.dst_ip[3] = buf->raw_ip_header.dst_ip[3];

  psh.zero = 0;
  psh.protocol = 17;

  copy_swap((uint8_t*)&(buf->raw_udp_header.length), (uint8_t*)&psh.udp_length, 2);

#if 1
  sum = calculate_checksum((uint8_t*)&psh, sizeof(pseudo_header)-sizeof(udp_header));

  copy_swap((uint8_t*)&(buf->raw_udp_header.src_port), &psh.ps_udp.src_port, 2);
  copy_swap((uint8_t*)&(buf->raw_udp_header.dst_port), &psh.ps_udp.dst_port, 2);
  copy_swap((uint8_t*)&(buf->raw_udp_header.length), &psh.ps_udp.length, 2);
  psh.ps_udp.checksum = 0;

  sum += calculate_checksum((uint8_t*)(&psh.ps_udp), sizeof(udp_header));

  if (total_length & 1)
  {  // Check if length is odd
    total_length++;  // Increment length to account for the extra byte
    data[total_length - 1] = 0;  // Pad with a zero byte
  }

  sum += calculate_checksum((uint8_t*)data, len);

  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
  sum = ~sum;

  //printf("Calculated Checksum = 0x%.4x\r\n\r\n", (uint16_t)sum);
#endif

  return sum;
}

uint16_t calculate_checksum(unsigned char *ptr, int nbytes)
{
  uint32_t sum;
  uint16_t temp;

  sum = 0;
  while (nbytes > 1)
  {
    temp = (uint16_t)(*ptr<<8)+*(ptr+1);
    sum += temp;
    ptr += 2;
    nbytes -= 2;
  }
  if (nbytes == 1)
  {
    temp = (uint16_t)(*ptr<<8);
    sum += temp;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);

  return (uint16_t)sum;
}
#endif
