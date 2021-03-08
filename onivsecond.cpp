#include "onivsecond.h"

OnivTunReq::OnivTunReq(uint32_t vni)
    : buf(nullptr),
    SupVerifyAlgSet(OnivCrypto::ListVerifyAlg()),
    SupKeyAgrAlgSet(OnivCrypto::ListKeyAgrAlg()),
    certs(OnivCrypto::CertChain())
{
    string UUID(OnivCrypto::UUID());
    common.type = CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_REQ);
    common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
    common.identifier = OnivCommon::count();

    bdi = vni;
    common.len = sizeof(bdi);

    ts = (uint64_t)system_clock::to_time_t(system_clock::now());
    common.len += sizeof(ts);

    PreVerifyAlg = OnivVerifyAlg::IV_AES_128_GCM_SHA256;
    common.len += sizeof(PreVerifyAlg) + SupVerifyAlgSet.LinearSize();

    PreKeyAgrAlg = OnivKeyAgrAlg::KA_SECP384R1;
    common.len += sizeof(PreKeyAgrAlg) + SupKeyAgrAlgSet.LinearSize();

    SigAlg = OnivCrypto::PreSigAlg();
    signature = OnivCrypto::GenSignature(UUID, SigAlg);
    common.len += sizeof(SigAlg) + signature.length();

    common.len += certs.LinearSize();

    common.total = common.len;
    common.offset = 0;

    memcpy(common.UUID, UUID.c_str(), UUID.length());

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
    common.linearization(p);
    p += common.LinearSize();

    *(uint32_t*)p = htonl(bdi);
    p += sizeof(bdi);
    *(uint64_t*)p = ts;
    p += sizeof(ts);

    *(uint16_t*)p = htons(CastTo16<OnivVerifyAlg>(PreVerifyAlg));
    p += sizeof(PreVerifyAlg);
    SupVerifyAlgSet.linearization(p);
    p += SupVerifyAlgSet.LinearSize();

    *(uint16_t*)p = htons(CastTo16<OnivKeyAgrAlg>(PreKeyAgrAlg));
    p += sizeof(PreKeyAgrAlg);
    SupKeyAgrAlgSet.linearization(p);
    p += SupVerifyAlgSet.LinearSize();

    *(uint16_t*)p = htons(CastTo16<OnivSigAlg>(SigAlg));
    p += sizeof(SigAlg);
    memcpy(p, signature.c_str(), signature.length());
    p += signature.length();

    certs.linearization(p);
}

OnivTunReq::OnivTunReq(const OnivPacket &packet) : buf(nullptr)
{
    if(packet.size() < OnivCommon::LinearSize()){
        return;
    }

    const uint8_t *p = (uint8_t*)packet.buffer();
    common.structuration(p);
    if(common.type != CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_REQ)){
        return;
    }
    if(common.len != packet.size() - OnivCommon::LinearSize()){
        return;
    }

    buf = new uint8_t[packet.size()];
    memcpy(buf, packet.buffer(), packet.size());
    p = buf + OnivCommon::LinearSize();

    bdi = ntohl(*(uint32_t*)p);
    p += sizeof(bdi);

    ts = *(uint64_t*)p;
    p += sizeof(ts);

    PreVerifyAlg = CastFrom16<OnivVerifyAlg>(ntohs(*(uint16_t*)p));
    p += sizeof(PreVerifyAlg);
    p += SupVerifyAlgSet.structuration(p);

    PreKeyAgrAlg = CastFrom16<OnivKeyAgrAlg>(ntohs(*(uint16_t*)p));
    p += sizeof(PreKeyAgrAlg);
    p += SupKeyAgrAlgSet.structuration(p);

    SigAlg = CastFrom16<OnivSigAlg>(ntohs(*(uint16_t*)p));
    p += sizeof(SigAlg);
    signature.assign((char*)p, OnivCrypto::SignatureSize(SigAlg));
    p += signature.length();

    certs.structuration(p);
}

OnivTunReq::~OnivTunReq()
{
    delete[] buf;
}

bool OnivTunReq::VerifySignature()
{
    return OnivCrypto::VerifySignature(certs.CertChain, signature);
}

const char* OnivTunReq::request()
{
    return (const char*)buf;
}

size_t OnivTunReq::size()
{
    return OnivCommon::LinearSize() + common.len;
}

OnivTunRes::OnivTunRes(uint32_t vni, const OnivKeyEntry *keyent) : buf(nullptr),
    certs(OnivCrypto::CertChain())
{
    string UUID(OnivCrypto::UUID());
    common.type = CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_RES);
    common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
    common.identifier = OnivCommon::count();

    bdi = vni;
    common.len = sizeof(bdi);

    ReqTs = keyent->ts, ResTs = (uint64_t)system_clock::to_time_t(system_clock::now());
    common.len += sizeof(ReqTs) + sizeof(ResTs);

    VerifyAlg = keyent->VerifyAlg, KeyAgrAlg = keyent->KeyAgrAlg, SigAlg = OnivCrypto::PreSigAlg();
    common.len += sizeof(VerifyAlg) + sizeof(KeyAgrAlg) + sizeof(SigAlg);

    pk = OnivCrypto::AcqPubKey(KeyAgrAlg);
    common.len += pk.length();

    signature = OnivCrypto::GenSignature(UUID + pk, SigAlg);
    common.len += signature.length();

    common.len += certs.LinearSize();

    common.total = common.len;
    common.offset = 0;

    memcpy(common.UUID, UUID.c_str(), UUID.length());

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
    common.linearization(p);
    p += common.LinearSize();

    *(uint32_t*)p = htonl(bdi);
    p += sizeof(bdi);
    *(uint64_t*)p = ReqTs;
    p += sizeof(ReqTs);
    *(uint64_t*)p = ResTs;
    p += sizeof(ResTs);
    
    *(uint16_t*)p = htons(CastTo16<OnivVerifyAlg>(VerifyAlg));
    p += sizeof(VerifyAlg);
    *(uint16_t*)p = htons(CastTo16<OnivKeyAgrAlg>(KeyAgrAlg));
    p += sizeof(KeyAgrAlg);
    *(uint16_t*)p = htons(CastTo16<OnivSigAlg>(SigAlg));
    p += sizeof(SigAlg);

    memcpy(p, pk.c_str(), pk.length());
    p += pk.length();
    memcpy(p, signature.c_str(), signature.length());
    p += signature.length();

    certs.linearization(p);
}

OnivTunRes::OnivTunRes(const OnivPacket &packet) : buf(nullptr)
{
    if(packet.size() < OnivCommon::LinearSize()){
        return;
    }

    const uint8_t *p = (uint8_t*)packet.buffer();
    common.structuration(p);
    if(common.type != CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_RES)){
        return;
    }
    if(common.len != packet.size() - OnivCommon::LinearSize()){
        return;
    }

    buf = new uint8_t[packet.size()];
    memcpy(buf, packet.buffer(), packet.size());
    p = buf + OnivCommon::LinearSize();

    bdi = ntohl(*(uint32_t*)p);
    p += sizeof(bdi);

    ReqTs = *(uint64_t*)p;
    p += sizeof(ReqTs);
    ResTs = *(uint64_t*)p;
    p += sizeof(ResTs);

    VerifyAlg = CastFrom16<OnivVerifyAlg>(ntohs(*(uint16_t*)p));
    p += sizeof(VerifyAlg);
    KeyAgrAlg = CastFrom16<OnivKeyAgrAlg>(ntohs(*(uint16_t*)p));
    p += sizeof(KeyAgrAlg);
    SigAlg = CastFrom16<OnivSigAlg>(ntohs(*(uint16_t*)p));
    p += sizeof(SigAlg);

    pk.assign((char*)p, OnivCrypto::PubKeySize(KeyAgrAlg));
    p += pk.length();

    signature.assign((char*)p, OnivCrypto::SignatureSize(SigAlg));
    p += signature.length();

    certs.structuration(p);
}

OnivTunRes::~OnivTunRes()
{
    delete[] buf;
}

bool OnivTunRes::VerifySignature()
{
    return OnivCrypto::VerifySignature(certs.CertChain, signature);
}

const char* OnivTunRes::response()
{
    return (const char*)buf;
}

size_t OnivTunRes::size()
{
    return OnivCommon::LinearSize() + common.len;
}

OnivTunRecord::OnivTunRecord(uint32_t vni, const OnivFrame &frame, const OnivKeyEntry *keyent) : buf(nullptr)
{
    string UUID(OnivCrypto::UUID());
    common.type = CastTo16<OnivPacketType>(OnivPacketType::ONIV_RECORD);

    bdi = vni;
    common.len = sizeof(bdi);

    if(keyent->UpdPk){
        common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_SEND);
        UpdTs = (uint64_t)system_clock::to_time_t(system_clock::now());
        KeyAgrAlg = keyent->KeyAgrAlg;
        pk = keyent->LocalPubKey;
        common.len += sizeof(UpdTs) + sizeof(KeyAgrAlg) + pk.length();
    }
    else if(keyent->AckPk){
        common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_SEND);
        UpdTs = keyent->ts;
        AckTs = (uint64_t)system_clock::to_time_t(system_clock::now());
        common.len += sizeof(UpdTs) + sizeof(AckTs);
    }
    else{
        common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
        common.len += 0;
    }
    common.identifier = OnivCommon::count();

    VerifyAlg = keyent->VerifyAlg;
    common.len += sizeof(VerifyAlg);

    data.assign(frame.buffer(), frame.size());
    code = OnivCrypto::MsgAuthCode(VerifyAlg, keyent->SessionKey, data);
    common.len += code.length();
    common.len += data.length();

    common.total = common.len;
    common.offset = 0;

    memcpy(common.UUID, UUID.c_str(), UUID.length());

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
    common.linearization(p);
    p += common.LinearSize();

    *(uint32_t*)p = htonl(bdi);
    p += sizeof(bdi);

    if(keyent->UpdPk){
        *(uint64_t*)p = UpdTs;
        p += sizeof(UpdTs);
        *(uint16_t*)p = htons(CastTo16<OnivKeyAgrAlg>(KeyAgrAlg));
        p += sizeof(KeyAgrAlg);
        memcpy(p, pk.c_str(), pk.length());
        p += pk.length();
    }
    else if(keyent->AckPk){
        *(uint64_t*)p = UpdTs;
        p += sizeof(UpdTs);
        *(uint64_t*)p = AckTs;
        p += sizeof(AckTs);
    }

    *(uint16_t*)p = htons(CastTo16<OnivVerifyAlg>(VerifyAlg));
    p += sizeof(VerifyAlg);

    memcpy(p, code.c_str(), code.length()), p += code.length();
    memcpy(p, data.c_str(), data.length());
}

OnivTunRecord::OnivTunRecord(const OnivPacket &packet) : buf(0)
{
    if(packet.size() < OnivCommon::LinearSize()){
        return;
    }

    const uint8_t *p = (uint8_t*)packet.buffer();
    common.structuration(p);
    if(common.type != CastTo16<OnivPacketType>(OnivPacketType::ONIV_RECORD)){
        return;
    }
    if(common.len != packet.size() - OnivCommon::LinearSize()){
        return;
    }

    buf = new uint8_t[packet.size()];
    memcpy(buf, packet.buffer(), packet.size());
    p = buf + OnivCommon::LinearSize();

    bdi = ntohl(*(uint32_t*)p);
    p += sizeof(bdi);

    if((common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_SEND)) != 0){
        UpdTs = *(uint64_t*)p;
        p += sizeof(UpdTs);
        KeyAgrAlg = CastFrom16<OnivKeyAgrAlg>(ntohs(*(uint16_t*)p));
        p += sizeof(KeyAgrAlg);
        pk.assign((char*)p, OnivCrypto::PubKeySize(KeyAgrAlg));
        p += pk.length();
    }
    else if((common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_SEND)) != 0){
        UpdTs = *(uint64_t*)p;
        p += sizeof(UpdTs);
        AckTs = *(uint64_t*)p;
        p += sizeof(AckTs);
    }

    VerifyAlg = CastFrom16<OnivVerifyAlg>(ntohs(*(uint16_t*)p));
    p += sizeof(uint16_t);

    code.assign((char*)p, OnivCrypto::MsgAuthCodeSize(VerifyAlg));
    p += code.length();
    data.assign((char*)p, buf + packet.size() - p);
}

OnivTunRecord::~OnivTunRecord()
{
    delete[] buf;
}

bool OnivTunRecord::UpdSend()
{
    return common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_SEND);
}

bool OnivTunRecord::AckSend()
{
    return common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_SEND);
}

bool OnivTunRecord::VerifyIdentity(const OnivKeyEntry *keyent)
{
    return code == OnivCrypto::MsgAuthCode(keyent->VerifyAlg, keyent->SessionKey, data);
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
    return OnivCommon::LinearSize() + common.len;
}

size_t OnivTunRecord::FrameSize()
{
    return data.length();
}
