#ifndef _ONIV_H_
#define _ONIV_H_

#include <cstring>
#include <string>
#include <vector>

#include <netinet/in.h>
#include <stdint.h>

using std::string;
using std::vector;

enum class OnivPacketType : uint16_t
{
    UNKNOWN,
    TUN_KA_REQ,
    TUN_KA_RES,
    TUN_KA_FIN,
    TUN_KA_FAIL,
    TUN_IV_ERR,
    ONIV_RECORD,
    LNK_KA_REQ,
    LNK_KA_RES,
    LNK_KA_FIN,
    LNK_KA_FAIL,
    LNK_IV_ERR,
};

enum class OnivPacketFlag : uint16_t
{
    NONE = 0x0000,
    UPD_ID = 0x0001,
    UPD_SEND = 0x0002,
    UPD_RECV = 0x0004,
    ACK_ID = 0x00010,
    ACK_SEND = 0x0020,
    ACK_RECV = 0x0040,
};

struct OnivCommon
{
    uint16_t type, flag;
    uint32_t len;
    uint8_t UUID[16];
};

uint8_t* LinearCommon(const OnivCommon &common, uint8_t *p);
void StructureCommon(const uint8_t *p, OnivCommon &common);

uint8_t* LinearCertChain(const vector<string> &CertChain, uint8_t *p);
size_t StructureCertChain(const uint8_t *p, vector<string> &CertChain);

void ConstructEncapHdr(uint8_t *hdr, uint16_t identifier, in_addr_t SrcAddr, in_addr_t DestAddr, in_port_t SrcPort, in_port_t DestPort, size_t OnivSize);
uint16_t IPChecksum(const uint8_t *buf, size_t len);
uint16_t UDPChecksum(const uint8_t *buf, size_t len);

#endif
