#include "onivfirst.h"

void OnivLnkReq::ConstructRequest(const OnivFrame &frame)
{
    if(frame.IsBroadcast()){
        return;
    }
    if(!frame.IsARP() && !frame.IsIP()){
        return;
    }

    string UUID(OnivCrypto::UUID());
    common.type = static_cast<uint16_t>(OnivPacketType::LNK_KA_REQ);
    common.flag = static_cast<uint16_t>(OnivPacketFlag::NONE);
    common.len = sizeof(PreVerifyAlg) + sizeof(SupVerifyAlg);
    common.len += sizeof(PreKeyAgrAlg) + sizeof(SupKeyAgrAlg);
    common.len += sizeof(ts);
    common.len += sizeof(uint16_t); // 证书链大小
    memcpy(common.UUID, UUID.c_str(), UUID.length());
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

    size_t Layer2HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
    HdrSize = Layer2HdrSize + 20 + 8;
    hdr = new uint8_t[HdrSize]; // 第一种身份信息相关报文全部使用自构建的IP协议封装
    memcpy(hdr, frame.Layer2Hdr(), Layer2HdrSize);
    *(uint16_t*)(hdr + 12) = htons(0x0800);
    ConstructEncapHdr(hdr + Layer2HdrSize, htons(OnivGlobal::OnivType),
        frame.SrcIPAddr(), frame.DestIPAddr(),
        htons(OnivGlobal::TunnelPortNo), htons(OnivGlobal::TunnelPortNo), size());

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
    p = LinearCommon(common, p);
    *(uint16_t*)p = htons(PreVerifyAlg), p += sizeof(PreVerifyAlg);
    *(uint16_t*)p = htons(SupVerifyAlg), p += sizeof(SupVerifyAlg);
    *(uint16_t*)p = htons(PreKeyAgrAlg), p += sizeof(PreKeyAgrAlg);
    *(uint16_t*)p = htons(SupKeyAgrAlg), p += sizeof(SupKeyAgrAlg);
    *(uint64_t*)p = ts, p += sizeof(ts);
    p = LinearCertChain(CertChain, p);
    memcpy(p, signature.c_str(), signature.length());
}

void OnivLnkReq::ParseRequest(const OnivFrame &frame)
{
    size_t OnivSize = frame.buffer() + frame.size() - frame.OnivHdr();
    if(frame.type() != OnivPacketType::LNK_KA_REQ){
        return;
    }
    if(OnivSize < sizeof(OnivCommon)){
        return;
    }

    const uint8_t *p = (uint8_t*)frame.OnivHdr();
    StructureCommon(p, common);
    if(common.len != OnivSize - sizeof(OnivCommon)){
        return;
    }

    buf = new uint8_t[OnivSize];
    memcpy(buf, frame.OnivHdr(), OnivSize);
    p = buf + sizeof(OnivCommon);

    PreVerifyAlg = ntohs(*(uint16_t*)p), p += sizeof(PreVerifyAlg);
    SupVerifyAlg = ntohs(*(uint16_t*)p), p += sizeof(SupVerifyAlg);
    PreKeyAgrAlg = ntohs(*(uint16_t*)p), p += sizeof(PreKeyAgrAlg);
    SupKeyAgrAlg = ntohs(*(uint16_t*)p), p += sizeof(SupKeyAgrAlg);
    ts = *(uint64_t*)p, p += sizeof(ts);
    p += StructureCertChain(p, CertChain);
    signature.assign((char*)p, buf + OnivSize - p);
}

OnivLnkReq::OnivLnkReq(const OnivFrame &frame) : hdr(nullptr), buf(nullptr), HdrSize(0)
{
    if(frame.IsLayer4Oniv()){
        ParseRequest(frame);
    }
    else{
        ConstructRequest(frame);
    }
}

OnivLnkReq::~OnivLnkReq()
{
    delete[] hdr;
    delete[] buf;
}

bool OnivLnkReq::VerifySignature()
{
    return OnivCrypto::VerifySignature(CertChain, signature);
}

OnivFrame OnivLnkReq::request()
{
    char frame[HdrSize + size()] = { 0 };
    memcpy(frame, hdr, HdrSize);
    memcpy(frame + HdrSize, buf, size());
    return OnivFrame(frame, HdrSize + size(), nullptr); // 不关心接收端口
}

size_t OnivLnkReq::size()
{
    return sizeof(OnivCommon) + common.len;
}

OnivLnkRes::OnivLnkRes(const OnivFrame &LnkReqFrame, const OnivKeyEntry *keyent) : hdr(nullptr), buf(nullptr), HdrSize(0)
{
    if(!LnkReqFrame.IsLayer4Oniv()){
        return;
    }

    string UUID(OnivCrypto::UUID());
    common.type = static_cast<uint16_t>(OnivPacketType::LNK_KA_RES);
    common.flag = static_cast<uint16_t>(OnivPacketFlag::NONE);
    common.len = sizeof(VerifyAlg) + sizeof(KeyAgrAlg);
    common.len += sizeof(RmdTp) + sizeof(AppTp);
    common.len += sizeof(ReqTs) + sizeof(ResTs);
    common.len += sizeof(uint16_t); // 证书链大小
    memcpy(common.UUID, UUID.c_str(), UUID.length());
    VerifyAlg = static_cast<uint16_t>(keyent->VerifyAlg);
    KeyAgrAlg = static_cast<uint16_t>(keyent->KeyAgrAlg);
    RmdTp = 1, AppTp = 1;
    ReqTs = 0, ResTs = 0;
    CertChain = OnivCrypto::CertChain();
    common.len += sizeof(uint16_t) * CertChain.size();
    for(size_t i = 0; i < CertChain.size(); i++)
    {
        common.len += CertChain[i].length();
    }
    pk = keyent->LocalPubKey;
    common.len += pk.length();
    signature = OnivCrypto::GenSignature(UUID + pk);
    common.len += signature.length();

    string SrcHwAddr = LnkReqFrame.DestHwAddr(), DestHwAddr = LnkReqFrame.SrcHwAddr();
    size_t Layer2HdrSize = LnkReqFrame.Layer3Hdr() - LnkReqFrame.Layer2Hdr();
    HdrSize = Layer2HdrSize + 20 + 8;
    hdr = new uint8_t[HdrSize]; // 第一种身份信息相关报文全部使用自构建的IP协议封装
    memcpy(hdr, DestHwAddr.c_str(), DestHwAddr.length());
    memcpy(hdr + DestHwAddr.length(), SrcHwAddr.c_str(), SrcHwAddr.length());
    *(uint16_t*)(hdr + 12) = htons(0x0800);
    ConstructEncapHdr(hdr + Layer2HdrSize, htons(OnivGlobal::OnivType),
        LnkReqFrame.DestIPAddr(), LnkReqFrame.SrcIPAddr(),
        LnkReqFrame.DestPort(), LnkReqFrame.SrcPort(), size());

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
    p = LinearCommon(common, p);
    *(uint16_t*)p = htons(VerifyAlg), p += sizeof(VerifyAlg);
    *(uint16_t*)p = htons(KeyAgrAlg), p += sizeof(KeyAgrAlg);
    *(uint16_t*)p = htons(RmdTp), p += sizeof(RmdTp);
    *(uint16_t*)p = htons(AppTp), p += sizeof(AppTp);
    *(uint64_t*)p = ReqTs, p += sizeof(ReqTs);
    *(uint64_t*)p = ResTs, p += sizeof(ResTs);
    p = LinearCertChain(CertChain, p);
    memcpy(p, pk.c_str(), pk.length()), p += pk.length();
    memcpy(p, signature.c_str(), signature.length());
}

OnivLnkRes::OnivLnkRes(const OnivFrame &frame) : hdr(nullptr), buf(nullptr), HdrSize(0)
{
    if(!frame.IsLayer4Oniv()){
        return;
    }
    
    size_t OnivSize = frame.buffer() + frame.size() - frame.OnivHdr();
    if(frame.type() != OnivPacketType::LNK_KA_RES){
        return;
    }
    if(OnivSize < sizeof(OnivCommon)){
        return;
    }

    const uint8_t *p = (uint8_t*)frame.OnivHdr();
    StructureCommon(p, common);
    if(common.len != OnivSize - sizeof(OnivCommon)){
        return;
    }

    buf = new uint8_t[OnivSize];
    memcpy(buf, frame.OnivHdr(), OnivSize);
    p = buf + sizeof(OnivCommon);

    VerifyAlg = ntohs(*(uint16_t*)p), p += sizeof(VerifyAlg);
    KeyAgrAlg = ntohs(*(uint16_t*)p), p += sizeof(KeyAgrAlg);
    RmdTp = ntohs(*(uint16_t*)p), p += sizeof(RmdTp);
    AppTp = ntohs(*(uint16_t*)p), p += sizeof(AppTp);
    ReqTs = *(uint64_t*)p, p += sizeof(ReqTs);
    ResTs = *(uint64_t*)p, p += sizeof(ResTs);
    p += StructureCertChain(p, CertChain);
    size_t PubKeySize = OnivCrypto::PubKeySize(static_cast<OnivKeyAgrAlg>(KeyAgrAlg));
    pk.assign((char*)p, PubKeySize), p += PubKeySize;
    signature.assign((char*)p, buf + OnivSize - p);
}

OnivLnkRes::~OnivLnkRes()
{
    delete[] hdr;
    delete[] buf;
}

bool OnivLnkRes::VerifySignature()
{
    return OnivCrypto::VerifySignature(CertChain, signature);
}

OnivFrame OnivLnkRes::response()
{
    char frame[HdrSize + size()] = { 0 };
    memcpy(frame, hdr, HdrSize);
    memcpy(frame + HdrSize, buf, size());
    return OnivFrame(frame, HdrSize + size(), nullptr); // 不关心接收端口
}

size_t OnivLnkRes::size()
{
    return sizeof(OnivCommon) + common.len;
}

void OnivLnkRecord::ConstructRecord(const OnivFrame &frame, OnivKeyEntry *keyent)
{
    if(frame.IsBroadcast()){
        return;
    }
    if(!frame.IsARP() && !frame.IsIP()){
        return;
    }

    string UUID(OnivCrypto::UUID());
    common.type = static_cast<uint16_t>(OnivPacketType::ONIV_RECORD);
    if(keyent->UpdPk){
        common.flag = static_cast<uint16_t>(OnivPacketFlag::UPD_SEND);
        UpdTs = 0;
        pk = keyent->LocalPubKey;
        common.len = sizeof(UpdTs) + pk.length();
    }
    else if(keyent->AckPk){
        common.flag = static_cast<uint16_t>(OnivPacketFlag::ACK_SEND);
        UpdTs = keyent->ts;
        AckTs = 0;
        common.len = sizeof(UpdTs) + sizeof(AckTs);
    }
    else{
        common.flag = static_cast<uint16_t>(OnivPacketFlag::NONE);
        common.len = 0;
    }
    memcpy(common.UUID, UUID.c_str(), UUID.length());

    if(frame.IsARP()){
        OriginProtocol = 0x0806;
    }
    else{
        OriginProtocol = 0x0800;
    }
    common.len += sizeof(OriginProtocol);

    data = frame.OriginUserData(); // data中包含原始的IP首部和四层首部
    code = OnivCrypto::MsgAuthCode(keyent->VerifyAlg, keyent->SessionKey, data);
    common.len += code.length();
    escrow = OnivCrypto::GenEscrowData(string(), keyent->VerifyAlg, keyent->SessionKey);
    common.len += escrow.length();
    common.len += data.length();

    size_t Layer2HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
    HdrSize = Layer2HdrSize + 20 + 8;
    hdr = new uint8_t[HdrSize]; // 第一种身份信息相关报文全部使用自构建的IP协议封装
    memcpy(hdr, frame.Layer2Hdr(), Layer2HdrSize);
    *(uint16_t*)(hdr + 12) = htons(0x0800);
    ConstructEncapHdr(hdr + Layer2HdrSize, htons(OnivGlobal::OnivType),
        frame.SrcIPAddr(), frame.DestIPAddr(),
        htons(OnivGlobal::TunnelPortNo), keyent->RemotePort, size());

    // 以网络字节序线性化
    buf = new uint8_t[size()];
    uint8_t *p = buf;
    p = LinearCommon(common, p);
    if(keyent->UpdPk){
        *(uint64_t*)p = UpdTs, p += sizeof(UpdTs);
        memcpy(p, pk.c_str(), pk.length()), p += pk.length();
    }
    else if(keyent->AckPk){
        *(uint64_t*)p = UpdTs, p += sizeof(UpdTs);
        *(uint64_t*)p = AckTs, p += sizeof(AckTs);
        keyent->lock();
        keyent->AckPk = false;
        keyent->unlock();
    }
    *(uint16_t*)p = htons(OriginProtocol), p += sizeof(OriginProtocol);
    memcpy(p, code.c_str(), code.length()), p += code.length();
    memcpy(p, escrow.c_str(), escrow.length()), p += escrow.length();
    memcpy(p, data.c_str(), data.length());
}

void OnivLnkRecord::ParseRecord(const OnivFrame &frame, OnivKeyEntry *keyent)
{
    HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
    hdr = new uint8_t[HdrSize];
    memcpy(hdr, frame.Layer2Hdr(), HdrSize);

    size_t OnivSize = frame.buffer() + frame.size() - frame.OnivHdr();
    if(frame.type() != OnivPacketType::ONIV_RECORD){
        return;
    }
    if(OnivSize < sizeof(OnivCommon)){
        return;
    }

    const uint8_t *p = (uint8_t*)frame.OnivHdr();
    StructureCommon(p, common);
    if(common.len != OnivSize - sizeof(OnivCommon)){
        return;
    }

    buf = new uint8_t[OnivSize];
    memcpy(buf, frame.OnivHdr(), OnivSize);
    p = buf + sizeof(OnivCommon);

    if(common.flag == static_cast<uint16_t>(OnivPacketFlag::UPD_SEND)){
        UpdTs = *(uint64_t*)p, p += sizeof(UpdTs);
        pk.assign((char*)p, OnivCrypto::PubKeySize(keyent->KeyAgrAlg)), p += pk.length();
        keyent->lock();
        keyent->RemotePubKey = pk;
        keyent->SessionKey = OnivCrypto::ComputeSessionKey(keyent->KeyAgrAlg, keyent->RemotePubKey, keyent->LocalPriKey);
        keyent->AckPk = true;
        keyent->ts = UpdTs;
        keyent->unlock();
    }
    else if(common.flag == static_cast<uint16_t>(OnivPacketFlag::ACK_SEND)){
        UpdTs = *(uint64_t*)p, p += sizeof(UpdTs);
        AckTs = *(uint64_t*)p, p += sizeof(AckTs);
        keyent->lock();
        keyent->UpdPk = false;
        keyent->ts = AckTs;
        keyent->unlock();
    }
    OriginProtocol = ntohs(*(uint16_t*)p), p += sizeof(OriginProtocol);
    *(uint16_t*)(hdr + 12) = htons(OriginProtocol);

    size_t CodeSize = OnivCrypto::MsgAuthCodeSize(keyent->VerifyAlg);
    size_t EscrowSize = OnivCrypto::EscrowDataSize(string(), keyent->VerifyAlg, keyent->SessionKey);
    code.assign((char*)p, CodeSize), p += CodeSize;
    escrow.assign((char*)p, EscrowSize), p += EscrowSize;
    data.assign((char*)p, buf + OnivSize - p);
}

OnivLnkRecord::OnivLnkRecord(const OnivFrame &frame, OnivKeyEntry *keyent) : hdr(nullptr), buf(nullptr), HdrSize(0)
{
    if(frame.IsLayer4Oniv()){
        ParseRecord(frame, keyent);
    }
    else{
        ConstructRecord(frame, keyent);
    }
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
    return OnivFrame(frame, HdrSize + data.length(), nullptr); // 不关心接收端口
}

size_t OnivLnkRecord::size()
{
    return sizeof(OnivCommon) + common.len;
}
