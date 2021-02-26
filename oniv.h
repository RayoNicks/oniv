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

char* LinearCommon(const OnivCommon &common, char *p);
void StructureCommon(const char *p, OnivCommon &common);

char* LinearCertChain(const vector<string> &CertChain, char *p);
size_t StructureCertChain(const char *p, vector<string> &CertChain);

#endif
