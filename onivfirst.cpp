#include "onivfirst.h"

void OnivLnkReq::ConstructRequest(const OnivFrame &frame)
{
    // 拷贝frame中的首部
    if(frame.IsBroadcast()){
        return;
    }
    if(frame.IsARP()){
        HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
        hdr = new char[HdrSize + 20 + 8]; // 最小IP首部加UDP首部
        memcpy(hdr, frame.Layer2Hdr(), HdrSize);
        *(uint16_t*)(hdr + 12) = htons(0x0800);
        *(hdr + HdrSize) = 0x45; // 版本和首部长度
        *(hdr + HdrSize + 1) = 0x00; // 服务类型
        *(uint16_t*)(hdr + HdrSize + 4) = htons(OnivGlobal::OnivType); // 标识
        *(uint16_t*)(hdr + HdrSize + 6) = htons(0x4000); // 分片
        *(hdr + HdrSize + 8) = 64; // 生存时间
        *(uint32_t*)(hdr + HdrSize + 12) = frame.SrcIPAddr();
        *(uint32_t*)(hdr + HdrSize + 16) = frame.DestIPAddr();
        HdrSize += 20; // HdrSize对齐到UDP首部
    }
    else if(frame.IsIP()){
        HdrSize = frame.Layer4Hdr() - frame.Layer2Hdr();
        hdr = new char[HdrSize + 8]; // UDP首部
        memcpy(hdr, frame.Layer2Hdr(), HdrSize);
    }
    else{
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
    // 修正hdr中的IP首部和UDP首部
    *(uint16_t*)(hdr + HdrSize) = htons(OnivGlobal::TunnelPortNo); // UDP源端口号
    *(uint16_t*)(hdr + HdrSize + 2) = htons(OnivGlobal::TunnelPortNo); // UDP目的端口号
    *(uint16_t*)(hdr + HdrSize + 4) = htons(8 + size()); // UDP首部长度字段
    *(uint16_t*)(hdr + HdrSize + 6) = 0; // 校验和设置为0
    *(uint16_t*)(hdr + 14 + 2) = htons(HdrSize - 14 + 8 + size()); // IP首部长度字段
    *(hdr + 14 + 9) = 0x11; // IP上层协议类型
    *(uint16_t*)(hdr + 14 + 10) = 0; // TODO IP首部校验和
    HdrSize += 8; // 原始HdrSize中不包含UDP首部

    // 以网络字节序线性化
    buf = new char[size()];
    char *p = buf;
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

    const char *p = frame.OnivHdr();
    StructureCommon(p, common);
    if(common.len != OnivSize - sizeof(OnivCommon)){
        return;
    }

    buf = new char[OnivSize];
    memcpy(buf, frame.OnivHdr(), OnivSize);
    p = buf + sizeof(OnivCommon);

    PreVerifyAlg = ntohs(*(uint16_t*)p), p += sizeof(PreVerifyAlg);
    SupVerifyAlg = ntohs(*(uint16_t*)p), p += sizeof(SupVerifyAlg);
    PreKeyAgrAlg = ntohs(*(uint16_t*)p), p += sizeof(PreKeyAgrAlg);
    SupKeyAgrAlg = ntohs(*(uint16_t*)p), p += sizeof(SupKeyAgrAlg);
    ts = *(uint64_t*)p, p += sizeof(ts);
    p += StructureCertChain(p, CertChain);
    signature.assign(p, buf + OnivSize - p); // TODO
}

OnivLnkReq::OnivLnkReq(const OnivFrame &frame) : hdr(nullptr), buf(nullptr), HdrSize(0)
{
    if(frame.IsOniv()){
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
    // TODO
    return true;
}
/*
vector<OnivFrame> OnivLnkReq::request()
{
    vector<OnivFrame> ret;
    char *frame, *p = buf;
    size_t RequestSize = size();
    while(RequestSize + HdrSize > OnivGlobal::TunnelMTU){
        frame = new char[OnivGlobal::TunnelMTU];
        memcpy(frame, hdr, HdrSize);
        memcpy(frame + HdrSize, p, OnivGlobal::TunnelMTU - HdrSize);
        ret.emplace_back(frame, OnivGlobal::TunnelMTU);
        p += OnivGlobal::TunnelMTU - HdrSize;
        RequestSize -= OnivGlobal::TunnelMTU - HdrSize;
        delete[] frame;
    }
    return ret;
}
*/
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
    HdrSize = LnkReqFrame.OnivHdr() - LnkReqFrame.Layer2Hdr();
    // 拷贝并调换frame中的首部地址信息
    OnivFrame LnkResFrame(LnkReqFrame.Layer2Hdr(), HdrSize, nullptr);
    LnkResFrame.reverse(); // 调换MAC地址，IP地址和端口号
    hdr = new char[HdrSize];
    memcpy(hdr, LnkResFrame.Layer2Hdr(), HdrSize);

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
    // 修正hdr中的IP首部和UDP首部
    *(uint16_t*)(hdr + HdrSize - 4) = htons(8 + size()); // UDP首部长度字段
    *(uint16_t*)(hdr + 14 + 2) = htons(LnkResFrame.IPHdrLen() + 8 + size()); // IP首部长度字段
    *(uint16_t*)(hdr + 14 + 10) = 0; // TODO IP首部校验和 

    // 以网络字节序线性化
    buf = new char[size()];
    char *p = buf;
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
    size_t OnivSize = frame.buffer() + frame.size() - frame.OnivHdr();
    if(frame.type() != OnivPacketType::LNK_KA_RES){
        return;
    }
    if(OnivSize < sizeof(OnivCommon)){
        return;
    }

    const char *p = frame.OnivHdr();
    StructureCommon(p, common);
    if(common.len != OnivSize - sizeof(OnivCommon)){
        return;
    }

    buf = new char[OnivSize];
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
    pk.assign(p, PubKeySize), p += PubKeySize;
    signature.assign(p, buf + OnivSize - p);
}

OnivLnkRes::~OnivLnkRes()
{
    delete[] hdr;
    delete[] buf;
}

bool OnivLnkRes::VerifySignature()
{
    // TODO
    return true;
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
    if(frame.IsARP()){
        HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
        hdr = new char[HdrSize + 20 + 8]; // 最小IP首部加UDP首部
        memcpy(hdr, frame.Layer2Hdr(), HdrSize);
        *(uint16_t*)(hdr + 12) = htons(0x0800);
        *(hdr + HdrSize) = 0x45; // 版本和首部长度
        *(hdr + HdrSize + 1) = 0x00; // 服务类型
        *(uint16_t*)(hdr + HdrSize + 4) = htons(OnivGlobal::OnivType); // 标识
        *(uint16_t*)(hdr + HdrSize + 6) = htons(0x4000); // 分片
        *(hdr + HdrSize + 8) = 64; // 生存时间
        *(uint32_t*)(hdr + HdrSize + 12) = frame.SrcIPAddr();
        *(uint32_t*)(hdr + HdrSize + 16) = frame.DestIPAddr();
        HdrSize += 20; // HdrSize对齐到UDP首部
    }
    else if(frame.IsIP()){
        HdrSize = frame.Layer4Hdr() - frame.Layer2Hdr();
        hdr = new char[HdrSize + 8]; // UDP首部
        memcpy(hdr, frame.Layer2Hdr(), HdrSize);
    }
    else{
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
        common.len += sizeof(OriginProtocol);
    }
    else if(frame.IsIP()){
        OriginProtocol = frame.Layer4Protocol();
        OriginLength = ntohs(*(uint16_t*)(hdr + 14 + 2));
        common.len += sizeof(OriginProtocol) + sizeof(OriginLength);
    }
    else{
        return;
    }
    data = frame.UserData(); // data中包含原始的4层首部
    code = OnivCrypto::MsgAuthCode(keyent->VerifyAlg, keyent->SessionKey, data);
    common.len += code.length();
    escrow;
    common.len += escrow.length();
    common.len += data.length();
    // 修正hdr中的IP首部和UDP首部
    *(uint16_t*)(hdr + HdrSize) = htons(OnivGlobal::TunnelPortNo); // UDP源端口号
    *(uint16_t*)(hdr + HdrSize + 2) = keyent->PortNo; // UDP目的端口号
    *(uint16_t*)(hdr + HdrSize + 4) = htons(8 + size()); // UDP首部长度字段
    *(uint16_t*)(hdr + HdrSize + 6) = 0; // 校验和设置为0
    *(uint16_t*)(hdr + 14 + 2) = htons(HdrSize - 14 + 8 + size()); // IP首部长度字段
    *(hdr + 14 + 9) = 0x11; // IP上层协议类型
    *(uint16_t*)(hdr + 14 + 10) = 0; // TODO IP首部校验和
    HdrSize += 8; // 原始HdrSize中不包含UDP首部

    // 以网络字节序线性化
    buf = new char[size()];
    char *p = buf;
    p = LinearCommon(common, p);
    if(keyent->UpdPk){
        *(uint64_t*)p = UpdTs, p += sizeof(UpdTs);
        memcpy(p, pk.c_str(), pk.length()), p += pk.length();
    }
    else if(keyent->AckPk){
        *(uint64_t*)p = UpdTs, p += sizeof(UpdTs);
        *(uint64_t*)p = AckTs, p += sizeof(AckTs);
        keyent->AckPk = false;
    }
    *(uint16_t*)p = htons(OriginProtocol), p += sizeof(OriginProtocol);
    if(frame.IsIP()){
        *(uint16_t*)p = htons(OriginLength), p += sizeof(OriginLength);
    }
    memcpy(p, code.c_str(), code.length()), p += code.length();
    memcpy(p, escrow.c_str(), escrow.length()), p += escrow.length();
    memcpy(p, data.c_str(), data.length());
}

void OnivLnkRecord::ParseRecord(const OnivFrame &frame, OnivKeyEntry *keyent)
{
    if(!frame.IsLayer4Oniv()){
        return;
    }
    HdrSize = frame.Layer4Hdr() - frame.Layer2Hdr();
    hdr = new char[HdrSize];
    memcpy(hdr, frame.Layer2Hdr(), HdrSize);

    size_t OnivSize = frame.buffer() + frame.size() - frame.OnivHdr();
    if(frame.type() != OnivPacketType::ONIV_RECORD){
        return;
    }
    if(OnivSize < sizeof(OnivCommon)){
        return;
    }

    const char *p = frame.OnivHdr();
    StructureCommon(p, common);
    if(common.len != OnivSize - sizeof(OnivCommon)){
        return;
    }

    buf = new char[OnivSize];
    memcpy(buf, frame.OnivHdr(), OnivSize);
    p = buf + sizeof(OnivCommon);

    if(common.flag == static_cast<uint16_t>(OnivPacketFlag::UPD_SEND)){
        UpdTs = *(uint64_t*)p, p += sizeof(UpdTs);
        pk.assign(p, OnivCrypto::PubKeySize(keyent->KeyAgrAlg)), p += pk.length();
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
    OriginProtocol = ntohs(*(uint16_t*)p), p += sizeof(OriginProtocol);
    if(OriginProtocol == 0x0806){
        *(uint16_t*)(hdr + 12) = htons(OriginProtocol);
        HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
    }
    else{
        OriginLength = ntohs(*(uint16_t*)p), p += sizeof(OriginLength);
        *(hdr + 14 + 9) = OriginProtocol & 0xFF;
        *(uint16_t*)(hdr + 14 + 2) = htons(OriginLength);
        *(uint16_t*)(hdr + 14 + 10) = 0; // TODO IP首部校验和
    }

    size_t CodeSize = OnivCrypto::MsgAuthCodeSize(keyent->VerifyAlg);
    size_t EscrowSize = 0;
    code.assign(p, CodeSize), p += CodeSize;
    escrow.assign(p, EscrowSize), p += EscrowSize;
    data.assign(p, buf + OnivSize - p);
}

OnivLnkRecord::OnivLnkRecord(const OnivFrame &frame, OnivKeyEntry *keyent) : hdr(nullptr), buf(nullptr), HdrSize(0)
{
    if(frame.IsOniv()){
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
