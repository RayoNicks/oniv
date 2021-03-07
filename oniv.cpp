#include "oniv.h"

size_t OnivCommon::LinearSize()
{
    return sizeof(type) + sizeof(flag)
        + sizeof(len) + sizeof(total) + sizeof(offset)
        + sizeof(UUID);
}

void OnivCommon::linearization(uint8_t *p)
{
    *(uint16_t*)p = htons(type), p += sizeof(type);
    *(uint16_t*)p = htons(flag), p += sizeof(flag);
    *(uint16_t*)p = htonl(len), p += sizeof(len);
    *(uint16_t*)p = htonl(total), p += sizeof(total);
    *(uint16_t*)p = htonl(offset), p += sizeof(offset);
    memcpy(p, UUID, sizeof(UUID)), p += sizeof(UUID);
}

size_t OnivCommon::structuration(const uint8_t *p)
{
    type = ntohs(*(uint16_t*)p), p += sizeof(type);
    flag = ntohs(*(uint16_t*)p), p += sizeof(flag);
    len = ntohl(*(uint32_t*)p), p += sizeof(len);

    memcpy(UUID, p, sizeof(UUID));
    return sizeof(OnivCommon);
}

void OnivCommon::ConstructEncapHdr(uint8_t *hdr, uint16_t identifier, in_addr_t SrcAddr, in_addr_t DestAddr, in_port_t SrcPort, in_port_t DestPort, size_t OnivSize)
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

uint16_t OnivCommon::IPChecksum(const uint8_t *buf, size_t len)
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

uint16_t OnivCommon::UDPChecksum(const uint8_t *buf, size_t len)
{
    // TODO
    return 0;
}

template <> OnivPacketType CastFrom16<OnivPacketType>(uint16_t u)
{
    switch(u)
    {
    case CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_REQ):
        return OnivPacketType::TUN_KA_REQ;
    case CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_RES):
        return OnivPacketType::TUN_KA_RES;
    case CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_FIN):
        return OnivPacketType::TUN_KA_FIN;
    case CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_FAIL):
        return OnivPacketType::TUN_KA_FAIL;
    case CastTo16<OnivPacketType>(OnivPacketType::TUN_IV_ERR):
        return OnivPacketType::TUN_IV_ERR;
    case CastTo16<OnivPacketType>(OnivPacketType::ONIV_RECORD):
        return OnivPacketType::ONIV_RECORD;
    case CastTo16<OnivPacketType>(OnivPacketType::LNK_KA_REQ):
        return OnivPacketType::LNK_KA_REQ;
    case CastTo16<OnivPacketType>(OnivPacketType::LNK_KA_RES):
        return OnivPacketType::LNK_KA_RES;
    case CastTo16<OnivPacketType>(OnivPacketType::LNK_KA_FIN):
        return OnivPacketType::LNK_KA_FIN;
    case CastTo16<OnivPacketType>(OnivPacketType::LNK_KA_FAIL):
        return OnivPacketType::LNK_KA_FAIL;
    case CastTo16<OnivPacketType>(OnivPacketType::LNK_IV_ERR):
        return OnivPacketType::LNK_IV_ERR;
    default:
        return OnivPacketType::UNKNOWN;
    }
}

template <> OnivVerifyAlg CastFrom16<OnivVerifyAlg>(uint16_t u)
{
    switch(u)
    {
    case CastTo16<OnivVerifyAlg>(OnivVerifyAlg::IV_AES_128_GCM_SHA256):
        return OnivVerifyAlg::IV_AES_128_GCM_SHA256;
    case CastTo16<OnivVerifyAlg>(OnivVerifyAlg::IV_AES_128_CCM_SHA256):
        return OnivVerifyAlg::IV_AES_128_CCM_SHA256;
    default:
        return OnivVerifyAlg::NONE;
    }
}

template <> OnivKeyAgrAlg CastFrom16<OnivKeyAgrAlg>(uint16_t u)
{
    if(CastTo16<OnivKeyAgrAlg>(OnivKeyAgrAlg::KA_SECP384R1) == u){
        return OnivKeyAgrAlg::KA_SECP384R1;
    }
    else if(CastTo16<OnivKeyAgrAlg>(OnivKeyAgrAlg::KA_SECP521R1) == u){
        return OnivKeyAgrAlg::KA_SECP521R1;
    }
    else{
        return OnivKeyAgrAlg::NONE;
    }
}

template <> OnivSigAlg CastFrom16<OnivSigAlg>(uint16_t u)
{
    switch(u)
    {
    case CastTo16<OnivSigAlg>(OnivSigAlg::RSA_PKCS1_SHA256):
        return OnivSigAlg::RSA_PKCS1_SHA256;
    case CastTo16<OnivSigAlg>(OnivSigAlg::RSA_PKCS1_SHA384):
        return OnivSigAlg::RSA_PKCS1_SHA384;
    case CastTo16<OnivSigAlg>(OnivSigAlg::RSA_PKCS1_SHA512):
        return OnivSigAlg::RSA_PKCS1_SHA512;
    case CastTo16<OnivSigAlg>(OnivSigAlg::ECDSA_SECP384R1_SHA384):
        return OnivSigAlg::ECDSA_SECP384R1_SHA384;
    case CastTo16<OnivSigAlg>(OnivSigAlg::ECDSA_SECP521R1_SHA512):
        return OnivSigAlg::ECDSA_SECP521R1_SHA512;
    default:
        return OnivSigAlg::NONE;
    }
}

OnivCertChain::OnivCertChain()
{

}

OnivCertChain::OnivCertChain(const vector<string> &certs)
{
    CertChain.assign(certs.begin(), certs.end());
}

// OnivCertChain& OnivCertChain::operator=(const vector<string> &certs)
// {
//     CertChain.assign(certs.begin(), certs.end());
//     return *this;
// }

size_t OnivCertChain::LinearSize()
{
    size_t CertsSize;
    for(const string &cert : CertChain)
    {
        CertsSize += cert.length();
    }
    return sizeof(uint16_t) + CertChain.size() * sizeof(uint16_t) + CertsSize;
}

void OnivCertChain::linearization(uint8_t *p)
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
}

size_t OnivCertChain::structuration(const uint8_t *p)
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
    CertChain.clear();
    for(size_t i = 0; i < CertNum; i++)
    {
        CertChain.push_back(string((char*)p, CertLengths[i]));
        p += CertLengths[i];
    }
    return p - orgin;
}
