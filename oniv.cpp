#include "oniv.h"

char* LinearCommon(const OnivCommon &common, char *p)
{
    *(uint16_t*)p = htons(common.type), p += sizeof(common.type);
    *(uint16_t*)p = htons(common.flag), p += sizeof(common.flag);
    *(uint32_t*)p = htonl(common.len), p += sizeof(common.len);
    memcpy(p, common.UUID, sizeof(common.UUID)), p += sizeof(common.UUID);
    return p;
}

void StructureCommon(const char *p, OnivCommon &common)
{
    common.type = ntohs(*(uint16_t*)p), p += sizeof(common.type);
    common.flag = ntohs(*(uint16_t*)p), p += sizeof(common.flag);
    common.len = ntohl(*(uint32_t*)p), p += sizeof(common.len);
    memcpy(common.UUID, p, sizeof(common.UUID));
}

char* LinearCertChain(const vector<string> &CertChain, char *p)
{
    uint16_t CertNum = CertChain.size();
    *(uint16_t*)p = htons(CertNum), p += sizeof(uint16_t);
    for(uint16_t i = 0; i < CertNum; i++)
    {
        *(uint16_t*)p = htons(CertChain[i].length());
        p += sizeof(uint16_t);
    }
    for(int16_t i = 0; i < CertNum; i++)
    {
        memcpy(p, CertChain[i].c_str(), CertChain[i].length());
        p += CertChain[i].length();
    }
    return p;
}

size_t StructureCertChain(const char *p, vector<string> &CertChain)
{
    const char *orgin = p;
    uint16_t CertNum = ntohs(*(uint16_t*)p);
    p += sizeof(uint16_t);
    vector<uint16_t> CertLengths;
    for(size_t i = 0; i < CertNum; i++)
    {
        CertLengths.push_back(ntohs(*(uint16_t*)p));
        p += sizeof(uint16_t);
    }
    for(size_t i = 0; i < CertNum; i++)
    {
        CertChain.push_back(string(p, CertLengths[i]));
        p += CertLengths[i];
    }
    return p - orgin;
}

uint16_t IPChecksum(const uint8_t *buf, size_t len)
{
    if(len % 2 != 0){
        return 0;
    }
    uint32_t cs = 0;
    uint16_t *p = (uint16_t*)buf;
    while(len > 0){
        cs += *p++;
        len -= 2;
    }
    cs = (cs >> 16) + (cs & 0xFFFF);
    cs += cs >> 16;
    return ~(cs & 0xFFFF);
}
