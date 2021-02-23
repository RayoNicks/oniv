#include "onivsecond.h"

OnivTunReq::OnivTunReq() : buf(nullptr)
{
    string UUID(OnivCrypto::UUID());
    common.type = static_cast<uint8_t>(OnivPacketType::TUN_KA_REQ);
    common.flag = static_cast<uint16_t>(OnivPacketFlag::NONE);
    common.len = sizeof(PreVerifyAlg) + sizeof(SupVerifyAlg);
    common.len += sizeof(PreKeyAgrAlg) + sizeof(SupKeyAgrAlg);
    common.len += sizeof(ts);
    common.len += sizeof(uint16_t); // 证书链大小
    memcpy(common.UUID, UUID.c_str(), UUID.length());
    PreVerifyAlg = 0, SupVerifyAlg = OnivCrypto::VerifyAlgSet();
    PreKeyAgrAlg = 0, SupKeyAgrAlg = OnivCrypto::KeyAgrAlgSet();
    ts = 0;
    CertChain = OnivCrypto::CertChain();
    common.len += sizeof(uint16_t) * CertChain.size();
    for(size_t i = 0; i < CertChain.size(); i++)
    {
        common.len += CertChain[i].length();
    }
    signature = OnivCrypto::GenSignature();
    common.len += sizeof(signature);

    // 以网络字节序线性化
    buf = new char[size()];
    char *p = buf;
    p = LinearCommon(common, p);
    *(uint16_t*)p = htons(PreVerifyAlg), p += sizeof(PreVerifyAlg) / sizeof(char);
    *(uint16_t*)p = htons(SupVerifyAlg), p += sizeof(SupVerifyAlg) / sizeof(char);
    *(uint16_t*)p = htons(PreKeyAgrAlg), p += sizeof(PreKeyAgrAlg) / sizeof(char);
    *(uint16_t*)p = htons(SupKeyAgrAlg), p += sizeof(SupKeyAgrAlg) / sizeof(char);
    *(uint64_t*)p = ts, p += sizeof(ts);
    p = LinearCertChain(CertChain, p);
    memcpy(p, signature.c_str(), signature.length());
}

OnivTunReq::OnivTunReq(const OnivPacket &packet)
{
    if(packet.type() != OnivPacketType::TUN_KA_REQ || packet.size() < sizeof(OnivCommon)){
        return;
    }

    const char *p = packet.data();
    StructureCommon(p, common);
    if(common.len != packet.size() - sizeof(OnivCommon)){
        return;
    }

    buf = new char[packet.size()];
    memcpy(buf, packet.data(), packet.size());
    p = buf + sizeof(OnivCommon) / sizeof(char);

    PreVerifyAlg = ntohs(*(uint16_t*)p), p += sizeof(PreVerifyAlg) / sizeof(char);
    SupVerifyAlg = ntohs(*(uint16_t*)p), p += sizeof(SupVerifyAlg) / sizeof(char);
    PreKeyAgrAlg = ntohs(*(uint16_t*)p), p += sizeof(PreKeyAgrAlg) / sizeof(char);
    SupKeyAgrAlg = ntohs(*(uint16_t*)p), p += sizeof(SupKeyAgrAlg) / sizeof(char);
    ts = *(uint64_t*)p, p += sizeof(ts) / sizeof(char);
    p += StructureCertChain(p, CertChain);
    signature.assign(p, packet.data() + packet.size() - p); // TODO
}

OnivTunReq::~OnivTunReq()
{
    delete[] buf;
}

bool OnivTunReq::AuthCert()
{
    // TODO
    return true;
}

char* OnivTunReq::request()
{
    return buf;
}

size_t OnivTunReq::size()
{
    return sizeof(OnivCommon) + common.len;
}

OnivTunRes::OnivTunRes(uint16_t va, uint16_t kaa)
{
    string UUID(OnivCrypto::UUID());
    common.type = static_cast<uint8_t>(OnivPacketType::TUN_KA_RES);
    common.flag = static_cast<uint16_t>(OnivPacketFlag::NONE);
    common.len = sizeof(VerifyAlg) + sizeof(KeyAgrAlg);
    common.len += sizeof(ReqTs) + sizeof(ResTs);
    common.len += sizeof(uint16_t);
    memcpy(common.UUID, UUID.c_str(), UUID.length());
    VerifyAlg = va, KeyAgrAlg = kaa;
    ResTs = 0, ResTs = 0;
    CertChain = OnivCrypto::CertChain();
    common.len += sizeof(uint16_t) * CertChain.size();
    for(size_t i = 0; i < CertChain.size(); i++)
    {
        common.len += CertChain[i].length();
    }
    signature = OnivCrypto::GenSignature();
    common.len += signature.length();
    pk = OnivCrypto::GetPublicKey(KeyAgrAlg);
    common.len += pk.length();

    // 以网络字节序线性化
    buf = new char[size()];
    char *p = buf;
    p = LinearCommon(common, p);
    *(uint16_t*)p = htons(VerifyAlg), p += sizeof(VerifyAlg) / sizeof(char);
    *(uint16_t*)p = htons(KeyAgrAlg), p += sizeof(KeyAgrAlg) / sizeof(char);
    *(uint64_t*)p = ReqTs, p += sizeof(ReqTs);
    *(uint64_t*)p = ResTs, p += sizeof(ResTs);
    p = LinearCertChain(CertChain, p);
    memcpy(p, signature.c_str(), signature.length()), p += signature.length();
    memcpy(p, pk.c_str(), pk.length());
}

OnivTunRes::OnivTunRes(const OnivPacket &packet)
{
    if(packet.type() != OnivPacketType::TUN_KA_RES || packet.size() < sizeof(OnivCommon)){
        return;
    }

    const char *p = packet.data();
    StructureCommon(p, common);
    if(common.len != packet.size() - sizeof(OnivCommon)){
        return;
    }

    buf = new char[packet.size()];
    memcpy(buf, packet.data(), packet.size());
    p = buf + sizeof(OnivCommon) / sizeof(char);

    VerifyAlg = ntohs(*(uint16_t*)p), p += sizeof(VerifyAlg) / sizeof(char);
    KeyAgrAlg = ntohs(*(uint16_t*)p), p += sizeof(KeyAgrAlg) / sizeof(char);
    ReqTs = *(uint64_t*)p, p += sizeof(ReqTs) / sizeof(char);
    ResTs = *(uint64_t*)p, p += sizeof(ResTs) / sizeof(char);
    p += StructureCertChain(p, CertChain);
    // TODO
    signature.assign(p, packet.data() + packet.size() - p); 
    pk.assign(p, packet.data() + packet.size() - p);
}

bool OnivTunRes::AuthCert()
{
    // TODO
    return true;
}

char* OnivTunRes::response()
{
    return buf;
}

size_t OnivTunRes::size()
{
    return sizeof(OnivCommon) + common.len;
}
