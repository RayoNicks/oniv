#include "onivfirst.h"
#include "oniventry.h"

OnivLnkReq::OnivLnkReq(const OnivFrame &frame)
    : hdr(nullptr), buf(nullptr), HdrSize(0),
    SupVerifyAlgSet(OnivCrypto::ListVerifyAlg()),
    SupKeyAgrAlgSet(OnivCrypto::ListKeyAgrAlg()),
    certs(OnivCrypto::CertChain())
{
    if(!frame.IsARP() && !frame.IsIP()){
        return;
    }

    string UUID(OnivCrypto::UUID());
    common.type = CastTo16<OnivPacketType>(OnivPacketType::LNK_KA_REQ);
    common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
    common.identifier = OnivCommon::count();

    ts = (uint64_t)system_clock::to_time_t(system_clock::now());
    common.len = sizeof(ts);

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

    // 第一种身份信息相关报文全部使用自构建的IP协议封装
    size_t Layer2HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
    HdrSize = Layer2HdrSize + 20 + 8;
    hdr = new uint8_t[HdrSize];
    memcpy(hdr, frame.Layer2Hdr(), Layer2HdrSize);
    *(uint16_t*)(hdr + 12) = htons(0x0800);
    OnivCommon::ConstructEncapHdr(hdr + Layer2HdrSize, htons(common.identifier),
        frame.SrcIPAddr(), frame.DestIPAddr(),
        htons(OnivGlobal::OnivPort), htons(OnivGlobal::OnivPort), size());

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
    common.linearization(p);
    p += common.LinearSize();

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

OnivLnkReq::OnivLnkReq(const char *OnivHdr, size_t OnivSize) : hdr(nullptr), buf(nullptr), HdrSize(0)
{
    if(OnivSize < OnivCommon::LinearSize()){
        return;
    }

    const uint8_t *p = (uint8_t*)OnivHdr;
    common.structuration(p);
    if(common.type != CastTo16<OnivPacketType>(OnivPacketType::LNK_KA_REQ)){
        return;
    }
    if(common.len != OnivSize - OnivCommon::LinearSize()){
        return;
    }

    buf = new uint8_t[OnivSize];
    memcpy(buf, OnivHdr, OnivSize);
    p = buf + OnivCommon::LinearSize();

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

OnivLnkReq::~OnivLnkReq()
{
    delete[] hdr;
    delete[] buf;
}

bool OnivLnkReq::VerifySignature()
{
    return OnivCrypto::VerifySignature(certs.CertChain, signature);
}

OnivFrame OnivLnkReq::request()
{
    // TODO
    char frame[HdrSize + size()] = { 0 };
    memcpy(frame, hdr, HdrSize);
    memcpy(frame + HdrSize, buf, size());
    return OnivFrame(frame, HdrSize + size(), nullptr); // 不关心接收端口
}

size_t OnivLnkReq::size()
{
    return OnivCommon::LinearSize() + common.len;
}

OnivLnkRes::OnivLnkRes(const OnivFrame &LnkReqFrame, const OnivKeyEntry *keyent)
    : hdr(nullptr), buf(nullptr), HdrSize(0), certs(OnivCrypto::CertChain())
{
    if(!LnkReqFrame.IsLayer4Oniv()){
        return;
    }

    string UUID(OnivCrypto::UUID());
    common.type = CastTo16<OnivPacketType>(OnivPacketType::LNK_KA_RES);
    common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
    common.identifier = OnivCommon::count();

    ReqTs = keyent->ts, ResTs = (uint64_t)system_clock::to_time_t(system_clock::now());
    common.len = sizeof(ReqTs) + sizeof(ResTs);

    RmdTp = 1, AppTp = 1;
    common.len += sizeof(RmdTp) + sizeof(AppTp);

    VerifyAlg = keyent->VerifyAlg, KeyAgrAlg = keyent->KeyAgrAlg, SigAlg = OnivCrypto::PreSigAlg();
    common.len += sizeof(VerifyAlg) + sizeof(KeyAgrAlg) + sizeof(SigAlg);

    pk = keyent->LocalPubKey;
    common.len += pk.length();

    signature = OnivCrypto::GenSignature(UUID + pk, SigAlg);
    common.len += signature.length();

    common.len += certs.LinearSize();

    common.total = common.len;
    common.offset = 0;

    memcpy(common.UUID, UUID.c_str(), UUID.length());

    // 第一种身份信息相关报文全部使用自构建的IP协议封装
    string SrcHwAddr = LnkReqFrame.DestHwAddr(), DestHwAddr = LnkReqFrame.SrcHwAddr();
    size_t Layer2HdrSize = LnkReqFrame.Layer3Hdr() - LnkReqFrame.Layer2Hdr();
    HdrSize = Layer2HdrSize + 20 + 8;
    hdr = new uint8_t[HdrSize];
    memcpy(hdr, DestHwAddr.c_str(), DestHwAddr.length());
    memcpy(hdr + DestHwAddr.length(), SrcHwAddr.c_str(), SrcHwAddr.length());
    *(uint16_t*)(hdr + 12) = htons(0x0800);
    OnivCommon::ConstructEncapHdr(hdr + Layer2HdrSize, htons(common.identifier),
        LnkReqFrame.DestIPAddr(), LnkReqFrame.SrcIPAddr(),
        LnkReqFrame.DestPort(), LnkReqFrame.SrcPort(), size());

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
    common.linearization(p);
    p += common.LinearSize();

    *(uint64_t*)p = ReqTs;
    p += sizeof(ReqTs);
    *(uint64_t*)p = ResTs;
    p += sizeof(ResTs);

    *(uint16_t*)p = htons(RmdTp);
    p += sizeof(RmdTp);
    *(uint16_t*)p = htons(AppTp);
    p += sizeof(AppTp);

    *(uint16_t*)p = htons(CastTo16<OnivVerifyAlg>(VerifyAlg));
    p += sizeof(VerifyAlg);
    *(uint16_t*)p = htons(CastTo16<OnivKeyAgrAlg>(KeyAgrAlg));
    p += sizeof(KeyAgrAlg);
    *(uint16_t*)p = htons(CastTo16<OnivSigAlg>(SigAlg));
    p += sizeof(SigAlg);

    memcpy(p, pk.c_str(), pk.length()), p += pk.length();
    memcpy(p, signature.c_str(), signature.length()), p += signature.length();

    certs.linearization(p);
}

OnivLnkRes::OnivLnkRes(const OnivFrame &frame) : hdr(nullptr), buf(nullptr), HdrSize(0)
{
    if(!frame.IsLayer4Oniv()){
        return;
    }

    size_t OnivSize = frame.buffer() + frame.size() - frame.OnivHdr();
    if(OnivSize < OnivCommon::LinearSize()){
        return;
    }

    const uint8_t *p = (uint8_t*)frame.OnivHdr();
    common.structuration(p);
    if(common.type != CastTo16<OnivPacketType>(OnivPacketType::LNK_KA_RES)){
        return;
    }
    if(common.len != OnivSize - OnivCommon::LinearSize()){
        return;
    }

    buf = new uint8_t[OnivSize];
    memcpy(buf, frame.OnivHdr(), OnivSize);
    p = buf + OnivCommon::LinearSize();

    ReqTs = *(uint64_t*)p;
    p += sizeof(ReqTs);
    ResTs = *(uint64_t*)p;
    p += sizeof(ResTs);

    RmdTp = ntohs(*(uint16_t*)p);
    p += sizeof(RmdTp);
    AppTp = ntohs(*(uint16_t*)p);
    p += sizeof(AppTp);

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

OnivLnkRes::~OnivLnkRes()
{
    delete[] hdr;
    delete[] buf;
}

bool OnivLnkRes::VerifySignature()
{
    return OnivCrypto::VerifySignature(certs.CertChain, signature);
}

OnivFrame OnivLnkRes::response()
{
    // TODO
    char frame[HdrSize + size()] = { 0 };
    memcpy(frame, hdr, HdrSize);
    memcpy(frame + HdrSize, buf, size());
    return OnivFrame(frame, HdrSize + size(), nullptr); // 不关心接收端口
}

size_t OnivLnkRes::size()
{
    return OnivCommon::LinearSize() + common.len;
}

OnivLnkRecord::OnivLnkRecord(const OnivFrame &frame, const OnivKeyEntry *keyent) : hdr(nullptr), buf(nullptr), HdrSize(0)
{
    if(!frame.IsARP() && !frame.IsIP()){
        return;
    }

    string UUID(OnivCrypto::UUID());
    common.type = CastTo16<OnivPacketType>(OnivPacketType::ONIV_RECORD);
    if(keyent->UpdPk){
        common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_SEND);
        UpdTs = (uint64_t)system_clock::to_time_t(system_clock::now());
        KeyAgrAlg = keyent->KeyAgrAlg;
        pk = keyent->LocalPubKey;
        common.len = sizeof(UpdTs) + sizeof(KeyAgrAlg) + pk.length();
    }
    else if(keyent->AckPk){
        common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_SEND);
        UpdTs = keyent->ts;
        AckTs = (uint64_t)system_clock::to_time_t(system_clock::now());
        common.len = sizeof(UpdTs) + sizeof(AckTs);
    }
    else{
        common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
        common.len = 0;
    }
    common.identifier = OnivCommon::count();

    if(frame.IsARP()){
        OriginProtocol = 0x0806;
    }
    else{
        OriginProtocol = 0x0800;
    }
    common.len += sizeof(OriginProtocol);

    VerifyAlg = keyent->VerifyAlg;
    common.len += sizeof(VerifyAlg);

    data = frame.OriginUserData(); // data中包含原始的IP首部和四层首部
    code = OnivCrypto::MsgAuthCode(VerifyAlg, keyent->SessionKey, data);
    trustee = keyent->ThirdName;
    escrow = OnivCrypto::GenEscrowData(OnivCrypto::AcqThirdPubKey(keyent->ThirdName), VerifyAlg, keyent->SessionKey);
    common.len += code.length();
    common.len += trustee.length() + 1; // 以'\0'结尾的字符串
    common.len += escrow.length();
    common.len += data.length();

    common.total = common.len;
    common.offset = 0;

    memcpy(common.UUID, UUID.c_str(), UUID.length());

    // 第一种身份信息相关报文全部使用自构建的IP协议封装
    size_t Layer2HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
    HdrSize = Layer2HdrSize + 20 + 8;
    hdr = new uint8_t[HdrSize];
    memcpy(hdr, frame.Layer2Hdr(), Layer2HdrSize);
    *(uint16_t*)(hdr + 12) = htons(0x0800);
    OnivCommon::ConstructEncapHdr(hdr + Layer2HdrSize, htons(common.identifier),
        frame.SrcIPAddr(), frame.DestIPAddr(),
        htons(OnivGlobal::OnivPort), keyent->RemotePort, size());

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
    common.linearization(p);
    p += common.LinearSize();

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

    *(uint16_t*)p = htons(OriginProtocol);
    p += sizeof(OriginProtocol);

    *(uint16_t*)p = htons(CastTo16<OnivVerifyAlg>(VerifyAlg));
    p += sizeof(VerifyAlg);

    memcpy(p, code.c_str(), code.length());
    p += code.length();
    memcpy(p, trustee.c_str(), trustee.length() + 1);
    p += trustee.length() + 1;
    memcpy(p, escrow.c_str(), escrow.length());
    p += escrow.length();
    memcpy(p, data.c_str(), data.length());
}

OnivLnkRecord::OnivLnkRecord(const OnivFrame &frame) : hdr(nullptr), buf(nullptr), HdrSize(0)
{
    if(!frame.IsLayer4Oniv()){
        return;
    }

    size_t OnivSize = frame.buffer() + frame.size() - frame.OnivHdr();
    if(OnivSize < OnivCommon::LinearSize()){
        return;
    }

    const uint8_t *p = (uint8_t*)frame.OnivHdr();
    common.structuration(p);
    if(common.type != CastTo16<OnivPacketType>(OnivPacketType::ONIV_RECORD)){
        return;
    }
    if(common.len != OnivSize - OnivCommon::LinearSize()){
        return;
    }

    HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
    hdr = new uint8_t[HdrSize];
    memcpy(hdr, frame.Layer2Hdr(), HdrSize);

    buf = new uint8_t[OnivSize];
    memcpy(buf, frame.OnivHdr(), OnivSize);
    p = buf + OnivCommon::LinearSize();

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

    OriginProtocol = ntohs(*(uint16_t*)p);
    p += sizeof(OriginProtocol);

    VerifyAlg = CastFrom16<OnivVerifyAlg>(ntohs(*(uint16_t*)p));
    p += sizeof(VerifyAlg);

    code.assign((char*)p, OnivCrypto::MsgAuthCodeSize(VerifyAlg));
    p += code.length();
    trustee.assign((char*)p);
    p += trustee.length() + 1; // 结尾'\0'
    escrow.assign((char*)p, OnivCrypto::EscrowDataSize(trustee));
    p += escrow.length();
    data.assign((char*)p, buf + OnivSize - p);
}

OnivLnkRecord::~OnivLnkRecord()
{
    delete[] hdr;
    delete[] buf;
}

bool OnivLnkRecord::VerifyIdentity(const OnivKeyEntry *keyent)
{
    return code == OnivCrypto::MsgAuthCode(keyent->VerifyAlg, keyent->SessionKey, data);
}

OnivFrame OnivLnkRecord::record()
{
    // TODO
    char frame[HdrSize + size()] = { 0 };
    memcpy(frame, hdr, HdrSize);
    memcpy(frame + HdrSize, buf, size());
    return OnivFrame(frame, HdrSize + size(), nullptr); // 不关心接收端口
}

OnivFrame OnivLnkRecord::frame()
{
    char frame[HdrSize + data.length()] = { 0 };
    memcpy(frame, hdr, HdrSize);
    memcpy(frame + HdrSize, data.c_str(), data.length());
    // TODO修正原始覆盖网络数据帧
    *(uint16_t*)(frame + 12) = htons(OriginProtocol);
    return OnivFrame(frame, HdrSize + data.length(), nullptr); // 不关心接收端口
}

size_t OnivLnkRecord::size()
{
    return OnivCommon::LinearSize() + common.len;
}
