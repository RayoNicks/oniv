#include "onivsecond.h"

OnivTunReq::OnivTunReq(uint32_t vni) : buf(nullptr)
{
    string UUID(OnivCrypto::UUID());
    common.type = static_cast<uint16_t>(OnivPacketType::TUN_KA_REQ);
    common.flag = static_cast<uint16_t>(OnivPacketFlag::NONE);
    common.len = sizeof(bdi);
    common.len += sizeof(PreVerifyAlg) + sizeof(SupVerifyAlg);
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
    common.len += signature.length();

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
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

OnivTunReq::OnivTunReq(const OnivPacket &packet) : buf(nullptr)
{
    if(packet.type() != OnivPacketType::TUN_KA_REQ || packet.size() < sizeof(OnivCommon)){
        return;
    }

    const uint8_t *p = (uint8_t*)packet.buffer();
    StructureCommon(p, common);
    if(common.len != packet.size() - sizeof(OnivCommon)){
        return;
    }

    buf = new uint8_t[packet.size()];
    memcpy(buf, packet.buffer(), packet.size());
    p = buf + sizeof(OnivCommon);

    bdi = ntohl(*(uint32_t*)p), p += sizeof(bdi);
    PreVerifyAlg = ntohs(*(uint16_t*)p), p += sizeof(PreVerifyAlg);
    SupVerifyAlg = ntohs(*(uint16_t*)p), p += sizeof(SupVerifyAlg);
    PreKeyAgrAlg = ntohs(*(uint16_t*)p), p += sizeof(PreKeyAgrAlg);
    SupKeyAgrAlg = ntohs(*(uint16_t*)p), p += sizeof(SupKeyAgrAlg);
    ts = *(uint64_t*)p, p += sizeof(ts);
    p += StructureCertChain(p, CertChain);
    signature.assign((char*)p, buf + packet.size() - p); // TODO
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

const char* OnivTunReq::request()
{
    return (const char*)buf;
}

size_t OnivTunReq::size()
{
    return sizeof(OnivCommon) + common.len;
}

OnivTunRes::OnivTunRes(uint32_t vni, OnivVerifyAlg va, OnivKeyAgrAlg kaa) : buf(nullptr)
{
    string UUID(OnivCrypto::UUID());
    common.type = static_cast<uint16_t>(OnivPacketType::TUN_KA_RES);
    common.flag = static_cast<uint16_t>(OnivPacketFlag::NONE);
    common.len = sizeof(bdi);
    common.len += sizeof(VerifyAlg) + sizeof(KeyAgrAlg);
    common.len += sizeof(ReqTs) + sizeof(ResTs);
    common.len += sizeof(uint16_t); // 证书链大小
    memcpy(common.UUID, UUID.c_str(), UUID.length());
    bdi = vni;
    VerifyAlg = static_cast<uint16_t>(va);
    KeyAgrAlg = static_cast<uint16_t>(kaa);
    ReqTs = 0, ResTs = 0;
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
    buf = new uint8_t[size()];
    uint8_t *p = buf;
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

OnivTunRes::OnivTunRes(const OnivPacket &packet) : buf(nullptr)
{
    if(packet.type() != OnivPacketType::TUN_KA_RES || packet.size() < sizeof(OnivCommon)){
        return;
    }

    const uint8_t *p = (uint8_t*)packet.buffer();
    StructureCommon(p, common);
    if(common.len != packet.size() - sizeof(OnivCommon)){
        return;
    }

    buf = new uint8_t[packet.size()];
    memcpy(buf, packet.buffer(), packet.size());
    p = buf + sizeof(OnivCommon);

    bdi = ntohl(*(uint32_t*)p), p += sizeof(bdi);
    VerifyAlg = ntohs(*(uint16_t*)p), p += sizeof(VerifyAlg);
    KeyAgrAlg = ntohs(*(uint16_t*)p), p += sizeof(KeyAgrAlg);
    ReqTs = *(uint64_t*)p, p += sizeof(ReqTs);
    ResTs = *(uint64_t*)p, p += sizeof(ResTs);
    p += StructureCertChain(p, CertChain);
    size_t PubKeySize = OnivCrypto::PubKeySize(static_cast<OnivKeyAgrAlg>(KeyAgrAlg));
    pk.assign((char*)p, PubKeySize), p += PubKeySize;
    signature.assign((char*)p, buf + packet.size() - p);
}

OnivTunRes::~OnivTunRes()
{
    delete[] buf;
}

bool OnivTunRes::VerifySignature()
{
    // TODO
    return true;
}

const char* OnivTunRes::response()
{
    return (const char*)buf;
}

size_t OnivTunRes::size()
{
    return sizeof(OnivCommon) + common.len;
}

OnivTunRecord::OnivTunRecord(uint32_t vni, const OnivFrame &frame, OnivKeyEntry *keyent) : buf(0)
{
    string UUID(OnivCrypto::UUID());
    common.type = static_cast<uint16_t>(OnivPacketType::ONIV_RECORD);
    common.len = sizeof(bdi);
    if(keyent->UpdPk){
        common.flag = static_cast<uint16_t>(OnivPacketFlag::UPD_SEND);
        UpdTs = 0;
        pk = keyent->LocalPubKey;
        common.len += sizeof(UpdTs) + pk.length();
    }
    else if(keyent->AckPk){
        common.flag = static_cast<uint16_t>(OnivPacketFlag::ACK_SEND);
        UpdTs = keyent->ts;
        AckTs = 0;
        common.len += sizeof(UpdTs) + sizeof(AckTs);
    }
    else{
        common.flag = static_cast<uint16_t>(OnivPacketFlag::NONE);
        common.len += 0;
    }
    memcpy(common.UUID, UUID.c_str(), UUID.length());
    bdi = vni;
    data.assign(frame.buffer(), frame.size());
    code = OnivCrypto::MsgAuthCode(keyent->VerifyAlg, keyent->SessionKey, data);
    common.len += code.length();
    common.len += data.length();

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
    p = LinearCommon(common, p);
    *(uint32_t*)p = htonl(bdi), p += sizeof(bdi);
    if(keyent->UpdPk){
        *(uint64_t*)p = UpdTs, p += sizeof(UpdTs);
        memcpy(p, pk.c_str(), pk.length()), p += pk.length();
    }
    else if(keyent->AckPk){
        *(uint64_t*)p = UpdTs, p += sizeof(UpdTs);
        *(uint64_t*)p = AckTs, p += sizeof(AckTs);
        keyent->AckPk = false;
    }
    memcpy(p, code.c_str(), code.length()), p += code.length();
    memcpy(p, data.c_str(), data.length());
}

OnivTunRecord::OnivTunRecord(const OnivPacket &packet, OnivKeyEntry *keyent) : buf(0)
{
    if(packet.type() != OnivPacketType::ONIV_RECORD || packet.size() < sizeof(OnivCommon)){
        return;
    }

    const uint8_t *p = (uint8_t*)packet.buffer();
    StructureCommon(p, common);
    if(common.len != packet.size() - sizeof(OnivCommon)){
        return;
    }

    buf = new uint8_t[packet.size()];
    memcpy(buf, packet.buffer(), packet.size());
    p = buf + sizeof(OnivCommon);

    bdi = ntohl(*(uint32_t*)p), p += sizeof(bdi);
    if(common.flag == static_cast<uint16_t>(OnivPacketFlag::UPD_SEND)){
        UpdTs = *(uint64_t*)p, p += sizeof(UpdTs);
        pk.assign((char*)p, OnivCrypto::PubKeySize(keyent->KeyAgrAlg)), p += pk.length();
        keyent->RemotePubKey = pk;
        keyent->SessionKey = OnivCrypto::ComputeSessionKey(keyent->KeyAgrAlg, keyent->RemotePubKey, keyent->LocalPriKey);
        keyent->AckPk = true;
        keyent->ts = UpdTs;
    }
    else if(common.flag == static_cast<uint16_t>(OnivPacketFlag::ACK_SEND)){
        UpdTs = *(uint64_t*)p, p += sizeof(UpdTs);
        AckTs = *(uint64_t*)p, p += sizeof(AckTs);
        keyent->UpdPk = false;
        keyent->ts = AckTs;
    }
    size_t CodeSize = OnivCrypto::MsgAuthCodeSize(keyent->VerifyAlg);
    code.assign((char*)p, CodeSize), p += CodeSize;
    data.assign((char*)p, buf + packet.size() - p);
}

OnivTunRecord::~OnivTunRecord()
{
    delete[] buf;
}

const char* OnivTunRecord::record()
{
    return (const char*)buf;
}

const char* OnivTunRecord::frame()
{
    return data.c_str();
}

size_t OnivTunRecord::size()
{
    return sizeof(OnivCommon) + common.len;
}

size_t OnivTunRecord::FrameSize()
{
    return data.length();
}
