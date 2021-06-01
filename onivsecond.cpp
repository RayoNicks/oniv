#include "onivsecond.h"

#include <cstring>

#include "onivcrypto.h"
#include "onivframe.h"
#include "oniventry.h"
#include "onivmessage.h"

using std::chrono::time_point;
using std::chrono::system_clock;
using std::string;

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

OnivTunReq::OnivTunReq(uint32_t bdi) : buf(nullptr)
{
    tc.common.type = CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_REQ);
    tc.common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
    tc.common.identifier = OnivCommon::count();

    tc.bdi = bdi;
    tc.common.len = sizeof(tc.bdi);

    tp = system_clock::now();
    tc.common.len += sizeof(tp);

    PreVerifyAlg = OnivCrypto::LocalAlg<OnivVerifyAlg>();
    SupVerifyAlgSet.insert(OnivCrypto::ListAlg<OnivVerifyAlg>());
    tc.common.len += sizeof(PreVerifyAlg) + SupVerifyAlgSet.LinearSize();

    PreKeyAgrAlg = OnivCrypto::LocalAlg<OnivKeyAgrAlg>();
    SupKeyAgrAlgSet.insert(OnivCrypto::ListAlg<OnivKeyAgrAlg>());
    tc.common.len += sizeof(PreKeyAgrAlg) + SupKeyAgrAlgSet.LinearSize();

    SigAlg = OnivCrypto::LocalAlg<OnivSigAlg>();
    signature.data(OnivCrypto::GenSignature(OnivCrypto::LocalUUID()));
    tc.common.len += sizeof(SigAlg) + signature.LinearSize();

    certs.assign(OnivCrypto::CertChain());
    tc.common.len += certs.LinearSize();
    memcpy(tc.common.UUID, OnivCrypto::LocalUUID().c_str(), sizeof(tc.common.UUID));

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
    tc.linearization(p);
    p += OnivTunCommon::LinearSize();

    *(uint64_t*)p = tp.time_since_epoch().count();
    p += sizeof(tp);

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

OnivTunReq::OnivTunReq(const OnivMessage &message) : buf(nullptr)
{
    if(message.size() < OnivTunCommon::LinearSize()){
        return;
    }

    const uint8_t *p = (uint8_t*)message.buffer();
    tc.structuration(p);
    if(tc.common.type != CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_REQ)){
        return;
    }
    if(tc.common.len != message.size() - OnivCommon::LinearSize()){
        return;
    }

    buf = new uint8_t[message.size()];
    memcpy(buf, message.buffer(), message.size());
    p = buf + OnivTunCommon::LinearSize();

    tp = time_point<system_clock>(system_clock::duration(*(uint64_t*)p));
    p += sizeof(tp);

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

OnivTunRes::OnivTunRes(uint32_t bdi, const OnivKeyEntry *keyent) : buf(nullptr)
{
    tc.common.type = CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_RES);
    tc.common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
    tc.common.identifier = OnivCommon::count();

    tc.bdi = bdi;
    tc.common.len = sizeof(tc.bdi);

    ReqTp = keyent->tp;
    ResTp = system_clock::now();
    tc.common.len += sizeof(ReqTp) + sizeof(ResTp);

    VerifyAlg = keyent->VerifyAlg, KeyAgrAlg = keyent->KeyAgrAlg;
    tc.common.len += sizeof(VerifyAlg) + sizeof(KeyAgrAlg);

    pk.data(keyent->LocalPubKey);
    tc.common.len += pk.LinearSize();

    SigAlg = OnivCrypto::LocalAlg<OnivSigAlg>();
    signature.data(OnivCrypto::GenSignature(OnivCrypto::LocalUUID() + pk.data()));
    tc.common.len += sizeof(SigAlg) + signature.LinearSize();

    certs.assign(OnivCrypto::CertChain());
    tc.common.len += certs.LinearSize();

    memcpy(tc.common.UUID, OnivCrypto::LocalUUID().c_str(), sizeof(tc.common.UUID));

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
    tc.linearization(p);
    p += OnivTunCommon::LinearSize();

    *(uint64_t*)p = ReqTp.time_since_epoch().count();
    p += sizeof(ReqTp);
    *(uint64_t*)p = ResTp.time_since_epoch().count();
    p += sizeof(ResTp);

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

OnivTunRes::OnivTunRes(const OnivMessage &message) : buf(nullptr)
{
    if(message.size() < OnivTunCommon::LinearSize()){
        return;
    }

    const uint8_t *p = (uint8_t*)message.buffer();
    tc.structuration(p);
    if(tc.common.type != CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_RES)){
        return;
    }
    if(tc.common.len != message.size() - OnivCommon::LinearSize()){
        return;
    }

    buf = new uint8_t[message.size()];
    memcpy(buf, message.buffer(), message.size());
    p = buf + OnivTunCommon::LinearSize();

    ReqTp = time_point<system_clock>(system_clock::duration(*(uint64_t*)p));
    p += sizeof(ReqTp);
    ResTp = time_point<system_clock>(system_clock::duration(*(uint64_t*)p));
    p += sizeof(ResTp);

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

OnivTunRec::OnivTunRec(uint32_t bdi, const OnivFrame &frame, const OnivKeyEntry *keyent) : buf(nullptr)
{
    if(keyent != nullptr){
        tc.common.type = CastTo16<OnivPacketType>(OnivPacketType::ONIV_RECORD);
    }
    else{
        tc.common.type = CastTo16<OnivPacketType>(OnivPacketType::ONIV_FRAME);
    }
    tc.common.identifier = OnivCommon::count();

    tc.bdi = bdi;
    tc.common.len = sizeof(tc.bdi);

    if(keyent != nullptr){
        if(keyent->UpdPk){
            tc.common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_PK);
            UpdTp = system_clock::now();
            KeyAgrAlg = keyent->KeyAgrAlg;
            pk.data(keyent->LocalPubKey);
            tc.common.len += sizeof(UpdTp) + sizeof(KeyAgrAlg) + pk.LinearSize();
        }
        else if(keyent->AckPk){
            tc.common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_PK);
            UpdTp = keyent->tp;
            AckTp = system_clock::now();
            tc.common.len += sizeof(UpdTp) + sizeof(AckTp);
        }
        else{
            tc.common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
            tc.common.len += 0;
        }
        VerifyAlg = keyent->VerifyAlg;
        tc.common.len += sizeof(VerifyAlg);
        code.data(string(OnivCrypto::MsgAuthCodeSize(), '\0')); // 占位
        tc.common.len += code.LinearSize();
    }
    else{
        tc.common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
        tc.common.len += 0;
    }

    data.assign(frame.buffer(), frame.size());
    tc.common.len += data.length();

    memcpy(tc.common.UUID, OnivCrypto::LocalUUID().c_str(), sizeof(tc.common.UUID));

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
    tc.linearization(p);
    p += OnivTunCommon::LinearSize();

    if(keyent != nullptr){
        if(keyent->UpdPk){
            *(uint64_t*)p = UpdTp.time_since_epoch().count();
            p += sizeof(UpdTp);
            *(uint16_t*)p = htons(CastTo16<OnivKeyAgrAlg>(KeyAgrAlg));
            p += sizeof(KeyAgrAlg);
            pk.linearization(p);
            p += pk.LinearSize();
        }
        else if(keyent->AckPk){
            *(uint64_t*)p = UpdTp.time_since_epoch().count();
            p += sizeof(UpdTp);
            *(uint64_t*)p = AckTp.time_since_epoch().count();
            p += sizeof(AckTp);
        }

        *(uint16_t*)p = htons(CastTo16<OnivVerifyAlg>(VerifyAlg));
        p += sizeof(VerifyAlg);

        string AssData((char*)buf, OnivTunCommon::LinearSize());
        string InitVector((char*)tc.common.UUID, sizeof(tc.common.UUID));
        InitVector.append((char*)buf + 4, 2); // identifier
        code.data(OnivCrypto::MsgAuthCode(VerifyAlg, keyent->SessionKey, data, InitVector, AssData));
        code.linearization(p);
        p += code.LinearSize();
    }

    memcpy(p, data.c_str(), data.length());
}

OnivTunRec::OnivTunRec(const OnivMessage &message) : buf(nullptr)
{
    if(message.size() < OnivCommon::LinearSize()){
        return;
    }

    const uint8_t *p = (uint8_t*)message.buffer();
    tc.structuration(p);
    if(tc.common.type != CastTo16<OnivPacketType>(OnivPacketType::ONIV_FRAME)
        && tc.common.type != CastTo16<OnivPacketType>(OnivPacketType::ONIV_RECORD)){
        return;
    }
    if(tc.common.len != message.size() - OnivCommon::LinearSize()){
        return;
    }

    buf = new uint8_t[message.size()];
    memcpy(buf, message.buffer(), message.size());
    p = buf + OnivTunCommon::LinearSize();

    if(tc.common.type == CastTo16<OnivPacketType>(OnivPacketType::ONIV_RECORD)){
        if((tc.common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_PK)) != 0){
            UpdTp = time_point<system_clock>(system_clock::duration(*(uint64_t*)p));;
            p += sizeof(UpdTp);
            KeyAgrAlg = CastFrom16<OnivKeyAgrAlg>(ntohs(*(uint16_t*)p));
            p += sizeof(KeyAgrAlg);
            p += pk.structuration(p);
        }
        else if((tc.common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_PK)) != 0){
            UpdTp = time_point<system_clock>(system_clock::duration(*(uint64_t*)p));
            p += sizeof(UpdTp);
            AckTp = time_point<system_clock>(system_clock::duration(*(uint64_t*)p));
            p += sizeof(AckTp);
        }

        VerifyAlg = CastFrom16<OnivVerifyAlg>(ntohs(*(uint16_t*)p));
        p += sizeof(uint16_t);

        p += code.structuration(p);
    }

    data.assign((char*)p, buf + message.size() - p);
}

OnivTunRec::~OnivTunRec()
{
    delete[] buf;
}

bool OnivTunRec::VerifyIdentity(const OnivKeyEntry *keyent)
{
    string AssData((char*)buf, OnivTunCommon::LinearSize());
    string InitVector((char*)tc.common.UUID, sizeof(tc.common.UUID));
    InitVector.append((char*)buf + 4, 2); // identifier
    return code.data() ==
        OnivCrypto::MsgAuthCode(keyent->VerifyAlg, keyent->SessionKey,
                            data, InitVector, AssData);
}

const uint8_t* OnivTunRec::record()
{
    return buf;
}

const char* OnivTunRec::frame()
{
    return data.c_str();
}

size_t OnivTunRec::size()
{
    return OnivCommon::LinearSize() + tc.common.len;
}

size_t OnivTunRec::FrameSize()
{
    return data.length();
}
