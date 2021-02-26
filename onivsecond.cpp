#include "onivsecond.h"

OnivTunReq::OnivTunReq(uint32_t vni) : buf(nullptr)
{
    string UUID(OnivCrypto::UUID());
    common.type = static_cast<uint16_t>(OnivPacketType::TUN_KA_REQ);
    common.flag = static_cast<uint16_t>(OnivPacketFlag::NONE);
    common.len = sizeof(PreVerifyAlg) + sizeof(SupVerifyAlg);
    common.len += sizeof(PreKeyAgrAlg) + sizeof(SupKeyAgrAlg);
    common.len += sizeof(ts);
    common.len += sizeof(uint16_t); // 证书链大小
    memcpy(common.UUID, UUID.c_str(), UUID.length());
    bdi = vni;
    PreVerifyAlg = static_cast<uint16_t>(OnivVerifyAlg::IV_SIMPLE_XOR);
    SupVerifyAlg = static_cast<uint16_t>(OnivCrypto::VerifyAlgSet());
    PreKeyAgrAlg = static_cast<uint16_t>(OnivKeyAgrAlg::KA_SIMPLE_XOR);
    SupKeyAgrAlg = static_cast<uint16_t>(OnivCrypto::KeyAgrAlgSet());
    ts = 0;
    CertChain = OnivCrypto::CertChain();
    common.len += sizeof(uint16_t) * CertChain.size();
    for(size_t i = 0; i < CertChain.size(); i++)
    {
        common.len += CertChain[i].length();
    }
    signature = OnivCrypto::GenSignature(UUID);
    common.len += sizeof(signature);

    // 以网络字节序线性化
    buf = new char[size()];
    char *p = buf;
    p = LinearCommon(common, p);
    *(uint32_t*)p = htonl(bdi), p += sizeof(bdi);
    *(uint16_t*)p = htons(PreVerifyAlg), p += sizeof(PreVerifyAlg);
    *(uint16_t*)p = htons(SupVerifyAlg), p += sizeof(SupVerifyAlg);
    *(uint16_t*)p = htons(PreKeyAgrAlg), p += sizeof(PreKeyAgrAlg);
    *(uint16_t*)p = htons(SupKeyAgrAlg), p += sizeof(SupKeyAgrAlg);
    *(uint64_t*)p = ts, p += sizeof(ts);
    p = LinearCertChain(CertChain, p);
    memcpy(p, signature.c_str(), signature.length());
}

OnivTunReq::OnivTunReq(const OnivPacket &packet)
{
    if(packet.type() != OnivPacketType::TUN_KA_REQ || packet.size() < sizeof(OnivCommon)){
        return;
    }

    const char *p = packet.buffer();
    StructureCommon(p, common);
    if(common.len != packet.size() - sizeof(OnivCommon)){
        return;
    }

    buf = new char[packet.size()];
    memcpy(buf, packet.buffer(), packet.size());
    p = buf + sizeof(OnivCommon);

    bdi = ntohl(*(uint32_t*)p), p += sizeof(bdi);
    PreVerifyAlg = ntohs(*(uint16_t*)p), p += sizeof(PreVerifyAlg);
    SupVerifyAlg = ntohs(*(uint16_t*)p), p += sizeof(SupVerifyAlg);
    PreKeyAgrAlg = ntohs(*(uint16_t*)p), p += sizeof(PreKeyAgrAlg);
    SupKeyAgrAlg = ntohs(*(uint16_t*)p), p += sizeof(SupKeyAgrAlg);
    ts = *(uint64_t*)p, p += sizeof(ts);
    p += StructureCertChain(p, CertChain);
    signature.assign(p, packet.buffer() + packet.size() - p); // TODO
}

OnivTunReq::~OnivTunReq()
{
    delete[] buf;
}

bool OnivTunReq::VerifySignature()
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

OnivTunRes::OnivTunRes(uint32_t vni, OnivVerifyAlg va, OnivKeyAgrAlg kaa)
{
    string UUID(OnivCrypto::UUID());
    common.type = static_cast<uint16_t>(OnivPacketType::TUN_KA_RES);
    common.flag = static_cast<uint16_t>(OnivPacketFlag::NONE);
    common.len = sizeof(VerifyAlg) + sizeof(KeyAgrAlg);
    common.len += sizeof(ReqTs) + sizeof(ResTs);
    common.len += sizeof(uint16_t); // 证书链大小
    memcpy(common.UUID, UUID.c_str(), UUID.length());
    bdi = vni;
    VerifyAlg = static_cast<uint16_t>(va);
    KeyAgrAlg = static_cast<uint16_t>(kaa);
    ResTs = 0, ResTs = 0;
    CertChain = OnivCrypto::CertChain();
    common.len += sizeof(uint16_t) * CertChain.size();
    for(size_t i = 0; i < CertChain.size(); i++)
    {
        common.len += CertChain[i].length();
    }
    pk = OnivCrypto::AcqPubKey(static_cast<OnivKeyAgrAlg>(KeyAgrAlg));
    common.len += pk.length();
    signature = OnivCrypto::GenSignature(UUID + pk);
    common.len += signature.length();

    // 以网络字节序线性化
    buf = new char[size()];
    char *p = buf;
    p = LinearCommon(common, p);
    *(uint32_t*)p = htonl(bdi), p += sizeof(bdi);
    *(uint16_t*)p = htons(VerifyAlg), p += sizeof(VerifyAlg);
    *(uint16_t*)p = htons(KeyAgrAlg), p += sizeof(KeyAgrAlg);
    *(uint64_t*)p = ReqTs, p += sizeof(ReqTs);
    *(uint64_t*)p = ResTs, p += sizeof(ResTs);
    p = LinearCertChain(CertChain, p);
    memcpy(p, pk.c_str(), pk.length()), p += pk.length();
    memcpy(p, signature.c_str(), signature.length());
}

OnivTunRes::OnivTunRes(const OnivPacket &packet)
{
    if(packet.type() != OnivPacketType::TUN_KA_RES || packet.size() < sizeof(OnivCommon)){
        return;
    }

    const char *p = packet.buffer();
    StructureCommon(p, common);
    if(common.len != packet.size() - sizeof(OnivCommon)){
        return;
    }

    buf = new char[packet.size()];
    memcpy(buf, packet.buffer(), packet.size());
    p = buf + sizeof(OnivCommon);

    bdi = ntohl(*(uint32_t*)p), p += sizeof(bdi);
    VerifyAlg = ntohs(*(uint16_t*)p), p += sizeof(VerifyAlg);
    KeyAgrAlg = ntohs(*(uint16_t*)p), p += sizeof(KeyAgrAlg);
    ReqTs = *(uint64_t*)p, p += sizeof(ReqTs);
    ResTs = *(uint64_t*)p, p += sizeof(ResTs);
    p += StructureCertChain(p, CertChain);
    // TODO
    pk.assign(p, packet.buffer() + packet.size() - p);
    signature.assign(p, packet.buffer() + packet.size() - p); 
}

bool OnivTunRes::VerifySignature()
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
