#include "oniv.h"

char* LinearCommon(const OnivCommon &common, char *p)
{
    *(uint16_t*)p = htons(common.type), p += sizeof(common.type) / sizeof(char);
    *(uint16_t*)p = htons(common.flag), p += sizeof(common.flag) / sizeof(char);
    *(uint16_t*)p = htons(common.len), p += sizeof(common.len) / sizeof(char);
    memcpy(p, common.UUID, sizeof(common.UUID)), p += sizeof(common.UUID) / sizeof(char);
    return p;
}

void StructureCommon(const char *p, OnivCommon &common)
{
    common.type = ntohs(*(uint16_t*)p), p += sizeof(common.type) / sizeof(char);
    common.flag = ntohs(*(uint16_t*)p), p += sizeof(common.flag) / sizeof(char);
    common.len = ntohs(*(uint16_t*)p), p += sizeof(common.len) / sizeof(char);
    memcpy(common.UUID, p, sizeof(common.UUID));
}

char* LinearCertChain(const vector<string> &CertChain, char *p)
{
    uint16_t CertNum = CertChain.size();
    *(uint16_t*)p = htons(CertNum), p += sizeof(uint16_t) / sizeof(char);
    for(uint16_t i = 0; i < CertNum; i++)
    {
        *(uint16_t*)p = htons(CertChain[i].size());
        p += sizeof(uint16_t) / sizeof(char);
    }
    for(int16_t i = 0; i < CertNum; i++)
    {
        memcpy(p, CertChain[i].c_str(), CertChain[i].size());
        p += CertChain[i].size();
    }
    return p;
}

size_t StructureCertChain(const char *p, vector<string> &CertChain)
{
    const char *orgin = p;
    uint16_t CertNum = ntohs(*(uint16_t*)p);
    p += sizeof(uint16_t) / sizeof(char);
    vector<uint16_t> CertLengths;
    for(size_t i = 0; i < CertNum; i++)
    {
        CertLengths.push_back(ntohs(*(uint16_t*)p));
        p += sizeof(uint16_t) / sizeof(char);
    }
    for(size_t i = 0; i < CertNum; i++)
    {
        CertChain.push_back(string(p, CertLengths[i]));
        p += CertLengths[i] / sizeof(char);
    }
    return p - orgin;
}
