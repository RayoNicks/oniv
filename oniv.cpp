#include "oniv.h"

uint8_t* LinearCommon(const OnivCommon &common, uint8_t *p)
{
    *(uint16_t*)p = htons(common.type), p += sizeof(common.type);
    *(uint16_t*)p = htons(common.flag), p += sizeof(common.flag);
    *(uint32_t*)p = htonl(common.len), p += sizeof(common.len);
    memcpy(p, common.UUID, sizeof(common.UUID)), p += sizeof(common.UUID);
    return p;
}

void StructureCommon(const uint8_t *p, OnivCommon &common)
{
    common.type = ntohs(*(uint16_t*)p), p += sizeof(common.type);
    common.flag = ntohs(*(uint16_t*)p), p += sizeof(common.flag);
    common.len = ntohl(*(uint32_t*)p), p += sizeof(common.len);
    memcpy(common.UUID, p, sizeof(common.UUID));
}

uint8_t* LinearCertChain(const vector<string> &CertChain, uint8_t *p)
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

size_t StructureCertChain(const uint8_t *p, vector<string> &CertChain)
{
    const uint8_t *orgin = p;
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
        CertChain.push_back(string((char*)p, CertLengths[i]));
        p += CertLengths[i];
    }
    return p - orgin;
}

void ConstructEncapHdr(uint8_t *hdr, uint16_t identifier, in_addr_t SrcAddr, in_addr_t DestAddr, in_port_t SrcPort, in_port_t DestPort, size_t OnivSize)
{
    const int IPHdrSize = 20;
    *(uint16_t*)(hdr + IPHdrSize) = SrcPort;
    *(uint16_t*)(hdr + IPHdrSize + 2) = DestPort;
    *(uint16_t*)(hdr + IPHdrSize + 4) = htons(8 + OnivSize); // UDP首部长度字段
    *(uint16_t*)(hdr + IPHdrSize + 6) = 0; // 校验和设置为0
    *(uint16_t*)(hdr + 2) = htons(IPHdrSize + 8 + OnivSize); // IP首部长度字段

    *hdr = 0x45; // 版本和首部长度
    *(hdr + 1) = 0x00; // 服务类型
    *(uint16_t*)(hdr + 4) = htons(identifier); // 标识
    *(uint16_t*)(hdr + 6) = htons(0x0000); // 分片
    *(hdr + 8) = 64; // 生存时间
    *(hdr + 9) = 0x11; // IP上层协议类型
    *(uint16_t*)(hdr + 10) = 0;
    *(uint32_t*)(hdr + 12) = SrcAddr;
    *(uint32_t*)(hdr + 16) = DestAddr;
    *(uint16_t*)(hdr + 10) = IPChecksum((uint8_t*)hdr, IPHdrSize); // IP首部校验和
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

uint16_t UDPChecksum(const uint8_t *buf, size_t len)
{
    // TODO
    return 0;
}
