#include "onivsecond.h"
#include "oniventry.h"

using std::chrono::system_clock;

void OnivTunCommon::linearization(uint8_t *p)
{
    common.linearization(p), p += OnivCommon::LinearSize();
    *(uint32_t*)p = htonl(bdi), p += sizeof(bdi);
}

size_t OnivTunCommon::structuration(const uint8_t *p)
{
    p += common.structuration(p);
    bdi = ntohl(*(uint32_t*)p), p += sizeof(bdi);
    return LinearSize();
}

size_t OnivTunCommon::LinearSize()
{
    return OnivCommon::LinearSize() + sizeof(bdi);
}

OnivTunReq::OnivTunReq(uint32_t vni) : buf(nullptr)
{
    tc.common.type = CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_REQ);
    tc.common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
    tc.common.identifier = OnivCommon::count();

    tc.bdi = vni;
    tc.common.len = sizeof(tc.bdi);

    ts = (uint64_t)system_clock::to_time_t(system_clock::now());
    tc.common.len += sizeof(ts);

    PreVerifyAlg = OnivCrypto::PreVerifyAlg();
    SupVerifyAlgSet.insert(OnivCrypto::ListVerifyAlg());
    tc.common.len += sizeof(PreVerifyAlg) + SupVerifyAlgSet.LinearSize();

    PreKeyAgrAlg = OnivCrypto::PreKeyAgrAlg();
    SupKeyAgrAlgSet.insert(OnivCrypto::ListKeyAgrAlg());
    tc.common.len += sizeof(PreKeyAgrAlg) + SupKeyAgrAlgSet.LinearSize();

    SigAlg = OnivCrypto::SigAlg();
    signature.data(OnivCrypto::GenSignature(OnivCrypto::UUID()));
    tc.common.len += sizeof(SigAlg) + signature.LinearSize();

    certs.assign(OnivCrypto::CertChain());
    tc.common.len += certs.LinearSize();
    memcpy(tc.common.UUID, OnivCrypto::UUID().c_str(), sizeof(tc.common.UUID));

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
    tc.linearization(p);
    p += OnivTunCommon::LinearSize();

    *(uint64_t*)p = ts;
    p += sizeof(ts);

    *(uint16_t*)p = htons(CastTo16<OnivVerifyAlg>(PreVerifyAlg));
    p += sizeof(PreVerifyAlg);
    SupVerifyAlgSet.linearization(p);
    p += SupVerifyAlgSet.LinearSize();

    *(uint16_t*)p = htons(CastTo16<OnivKeyAgrAlg>(PreKeyAgrAlg));
    p += sizeof(PreKeyAgrAlg);
    SupKeyAgrAlgSet.linearization(p);
    p += SupKeyAgrAlgSet.LinearSize();

    *(uint16_t*)p = htons(CastTo16<OnivSigAlg>(SigAlg));
    p += sizeof(SigAlg);
    signature.linearization(p);
    p += signature.LinearSize();

    certs.linearization(p);
}

OnivTunReq::OnivTunReq(const OnivPacket &packet) : buf(nullptr)
{
    if(packet.size() < OnivTunCommon::LinearSize()){
        return;
    }

    const uint8_t *p = (uint8_t*)packet.buffer();
    tc.structuration(p);
    if(tc.common.type != CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_REQ)){
        return;
    }
    if(tc.common.len != packet.size() - OnivCommon::LinearSize()){
        return;
    }

    buf = new uint8_t[packet.size()];
    memcpy(buf, packet.buffer(), packet.size());
    p = buf + OnivTunCommon::LinearSize();

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
    p += signature.structuration(p);

    certs.structuration(p);
}

OnivTunReq::~OnivTunReq()
{
    delete[] buf;
}

bool OnivTunReq::VerifySignature()
{
    return OnivCrypto::VerifySignature(certs.CertChain,
        string((char*)tc.common.UUID, sizeof(tc.common.UUID)),
        signature.data());
}

const uint8_t* OnivTunReq::request()
{
    return buf;
}

size_t OnivTunReq::size()
{
    return OnivCommon::LinearSize() + tc.common.len;
}

OnivTunRes::OnivTunRes(uint32_t vni, const OnivKeyEntry *keyent) : buf(nullptr)
{
    tc.common.type = CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_RES);
    tc.common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
    tc.common.identifier = OnivCommon::count();

    tc.bdi = vni;
    tc.common.len = sizeof(tc.bdi);

    ReqTs = keyent->ts, ResTs = (uint64_t)system_clock::to_time_t(system_clock::now());
    tc.common.len += sizeof(ReqTs) + sizeof(ResTs);

    VerifyAlg = keyent->VerifyAlg, KeyAgrAlg = keyent->KeyAgrAlg;
    tc.common.len += sizeof(VerifyAlg) + sizeof(KeyAgrAlg);

    pk.data(keyent->LocalPubKey);
    tc.common.len += pk.LinearSize();

    SigAlg = OnivCrypto::SigAlg();
    signature.data(OnivCrypto::GenSignature(OnivCrypto::UUID() + pk.data()));
    tc.common.len += sizeof(SigAlg) + signature.LinearSize();

    certs.assign(OnivCrypto::CertChain());
    tc.common.len += certs.LinearSize();

    memcpy(tc.common.UUID, OnivCrypto::UUID().c_str(), sizeof(tc.common.UUID));

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
    tc.linearization(p);
    p += OnivTunCommon::LinearSize();

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

    pk.linearization(p);
    p += pk.LinearSize();

    signature.linearization(p);
    p += signature.LinearSize();

    certs.linearization(p);
}

OnivTunRes::OnivTunRes(const OnivPacket &packet) : buf(nullptr)
{
    if(packet.size() < OnivTunCommon::LinearSize()){
        return;
    }

    const uint8_t *p = (uint8_t*)packet.buffer();
    tc.structuration(p);
    if(tc.common.type != CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_RES)){
        return;
    }
    if(tc.common.len != packet.size() - OnivCommon::LinearSize()){
        return;
    }

    buf = new uint8_t[packet.size()];
    memcpy(buf, packet.buffer(), packet.size());
    p = buf + OnivTunCommon::LinearSize();

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

    p += pk.structuration(p);

    p += signature.structuration(p);

    certs.structuration(p);
}

OnivTunRes::~OnivTunRes()
{
    delete[] buf;
}

bool OnivTunRes::VerifySignature()
{
    return OnivCrypto::VerifySignature(certs.CertChain,
        string((char*)tc.common.UUID, sizeof(tc.common.UUID)) + pk.data(),
        signature.data());
}

const uint8_t* OnivTunRes::response()
{
    return buf;
}

size_t OnivTunRes::size()
{
    return OnivCommon::LinearSize() + tc.common.len;
}

OnivTunRecord::OnivTunRecord(uint32_t vni, const OnivFrame &frame, const OnivKeyEntry *keyent) : buf(nullptr)
{
    tc.common.type = CastTo16<OnivPacketType>(OnivPacketType::ONIV_RECORD);
    tc.bdi = vni;
    tc.common.len = sizeof(tc.bdi);

    if(keyent->UpdPk){
        tc.common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_PK);
        UpdTs = (uint64_t)system_clock::to_time_t(system_clock::now());
        KeyAgrAlg = keyent->KeyAgrAlg;
        pk.data(keyent->LocalPubKey);
        tc.common.len = sizeof(UpdTs) + sizeof(KeyAgrAlg) + pk.LinearSize();
    }
    else if(keyent->AckPk){
        tc.common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_PK);
        UpdTs = keyent->ts;
        AckTs = (uint64_t)system_clock::to_time_t(system_clock::now());
        tc.common.len = sizeof(UpdTs) + sizeof(AckTs);
    }
    else{
        tc.common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
        tc.common.len = 0;
    }
    tc.common.identifier = OnivCommon::count();
    tc.bdi = vni;

    VerifyAlg = keyent->VerifyAlg;
    tc.common.len += sizeof(VerifyAlg);

    code.data(string(OnivCrypto::MsgAuchCodeSize(), '\0')); // 占位
    data.assign(frame.buffer(), frame.size());
    tc.common.len += code.LinearSize();
    tc.common.len += data.length();

    memcpy(tc.common.UUID, OnivCrypto::UUID().c_str(), sizeof(tc.common.UUID));

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
    tc.linearization(p);
    p += OnivTunCommon::LinearSize();

    if(keyent->UpdPk){
        *(uint64_t*)p = UpdTs;
        p += sizeof(UpdTs);
        *(uint16_t*)p = htons(CastTo16<OnivKeyAgrAlg>(KeyAgrAlg));
        p += sizeof(KeyAgrAlg);
        pk.linearization(p);
        p += pk.LinearSize();
    }
    else if(keyent->AckPk){
        *(uint64_t*)p = UpdTs;
        p += sizeof(UpdTs);
        *(uint64_t*)p = AckTs;
        p += sizeof(AckTs);
    }

    *(uint16_t*)p = htons(CastTo16<OnivVerifyAlg>(VerifyAlg));
    p += sizeof(VerifyAlg);

    string AssData((char*)buf, OnivTunCommon::LinearSize());
    string InitVector((char*)tc.common.UUID, sizeof(tc.common.UUID));
    InitVector.append((char*)buf + 4, 2); // identifier
    code.data(OnivCrypto::MsgAuthCode(VerifyAlg, keyent->SessionKey, data, InitVector, AssData));
    code.linearization(p);
    p += code.LinearSize();

    memcpy(p, data.c_str(), data.length());
}

OnivTunRecord::OnivTunRecord(const OnivPacket &packet) : buf(0)
{
    if(packet.size() < OnivCommon::LinearSize()){
        return;
    }

    const uint8_t *p = (uint8_t*)packet.buffer();
    tc.structuration(p);
    if(tc.common.type != CastTo16<OnivPacketType>(OnivPacketType::ONIV_RECORD)){
        return;
    }
    if(tc.common.len != packet.size() - tc.LinearSize()){
        return;
    }

    buf = new uint8_t[packet.size()];
    memcpy(buf, packet.buffer(), packet.size());
    p = buf + tc.LinearSize();

    if((tc.common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_PK)) != 0){
        UpdTs = *(uint64_t*)p;
        p += sizeof(UpdTs);
        KeyAgrAlg = CastFrom16<OnivKeyAgrAlg>(ntohs(*(uint16_t*)p));
        p += sizeof(KeyAgrAlg);
        p += pk.structuration(p);
    }
    else if((tc.common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_PK)) != 0){
        UpdTs = *(uint64_t*)p;
        p += sizeof(UpdTs);
        AckTs = *(uint64_t*)p;
        p += sizeof(AckTs);
    }

    VerifyAlg = CastFrom16<OnivVerifyAlg>(ntohs(*(uint16_t*)p));
    p += sizeof(uint16_t);

    p += code.structuration(p);

    data.assign((char*)p, buf + packet.size() - p);
}

OnivTunRecord::~OnivTunRecord()
{
    delete[] buf;
}

bool OnivTunRecord::VerifyIdentity(const OnivKeyEntry *keyent)
{
    string AssData((char*)buf, OnivTunCommon::LinearSize());
    string InitVector((char*)tc.common.UUID, sizeof(tc.common.UUID));
    InitVector.append((char*)buf + 4, 2); // identifier
    return code.data() ==
        OnivCrypto::MsgAuthCode(keyent->VerifyAlg, keyent->SessionKey,
                            data, InitVector, AssData);
}

const uint8_t* OnivTunRecord::record()
{
    return buf;
}

const char* OnivTunRecord::frame()
{
    return data.c_str();
}

size_t OnivTunRecord::size()
{
    return OnivTunCommon::LinearSize() + tc.common.len;
}

size_t OnivTunRecord::FrameSize()
{
    return data.length();
}
