#pragma once
#include "include.h"

#pragma pack(push,1)

struct Pseudoheader{
    uint32_t srcIP;
    uint32_t destIP;
    uint8_t reserved{0};
    uint8_t protocol;
    uint16_t TCPLen;
};


struct icmphdr
{
  u_int8_t type;		/* message type */
  u_int8_t code;		/* type sub-code */
  u_int16_t checksum;
  union
  {
    struct
    {
      u_int16_t	id;
      u_int16_t	sequence;
    } echo;			/* echo datagram */
    u_int32_t	gateway;	/* gateway address */
    struct
    {
      u_int16_t	__glibc_reserved;
      u_int16_t	mtu;
    } frag;			/* path mtu discovery */
  } un;
};

#pragma pack(pop)

#define CARRY 65536
uint16_t calculate(uint16_t* data, int dataLen);
uint16_t calTCPChecksum(uint8_t* data, int dataLen);   // need to data pointer at IP Header
uint16_t calIPChecksum(uint8_t* data);                  // need to data pointer at IP Header
uint16_t calICMPChecksum(uint8_t* data, int dataLen);   // need to data pointer at IP Header
uint16_t calUDPChecksum(uint8_t* data, int dataLen);   // need to data pointer at IP Header

