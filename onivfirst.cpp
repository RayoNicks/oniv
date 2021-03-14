#include "onivfirst.h"
#include "oniventry.h"

OnivLnkReq::OnivLnkReq(const OnivFrame &frame) : buf(nullptr)
{
    if(!frame.IsARP() && !frame.IsIP()){
        return;
    }

    common.type = CastTo16<OnivPacketType>(OnivPacketType::LNK_KA_REQ);
    common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
    common.identifier = OnivCommon::count();

    ts = (uint64_t)system_clock::to_time_t(system_clock::now());
    common.total = sizeof(ts);

    PreVerifyAlg = OnivCrypto::PreVerifyAlg();
    SupVerifyAlgSet.insert(OnivCrypto::ListVerifyAlg());
    common.total += sizeof(PreVerifyAlg) + SupVerifyAlgSet.LinearSize();

    PreKeyAgrAlg = OnivCrypto::PreKeyAgrAlg();
    SupKeyAgrAlgSet.insert(OnivCrypto::ListKeyAgrAlg());
    common.total += sizeof(PreKeyAgrAlg) + SupKeyAgrAlgSet.LinearSize();

    SigAlg = OnivCrypto::SigAlg();
    signature.data(OnivCrypto::GenSignature(OnivCrypto::UUID()));
    common.total += sizeof(SigAlg) + signature.LinearSize();

    certs.assign(OnivCrypto::CertChain());
    common.total += certs.LinearSize();

    memcpy(common.UUID, OnivCrypto::UUID().c_str(), sizeof(common.UUID));

    // 使用自构建的IP协议封装
    size_t Layer2HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
    size_t EncapHdrSize = Layer2HdrSize + 20 + 8;
    size_t HdrSizeWithOnivHdr = EncapHdrSize + OnivCommon::LinearSize();
    uint8_t hdr[HdrSizeWithOnivHdr] = { 0 };
    memcpy(hdr, frame.Layer2Hdr(), Layer2HdrSize);
    *(uint16_t*)(hdr + 12) = htons(0x0800);

    // 以网络字节序线性化
    buf = new uint8_t[common.total];
    uint8_t *p = buf;

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
    signature.linearization(p);
    p += signature.LinearSize();

    certs.linearization(p);

    // 分片
    common.offset = 0;
    common.len = OnivGlobal::AdapterMTU - HdrSizeWithOnivHdr;
    while(common.offset + common.len < common.total){
        OnivCommon::ConstructEncapHdr(hdr + Layer2HdrSize, OnivCommon::count(),
            frame.SrcIPAddr(), frame.DestIPAddr(),
            htons(OnivGlobal::OnivPort), htons(OnivGlobal::OnivPort),
            OnivCommon::LinearSize() + common.len);
        common.linearization(hdr + EncapHdrSize);
        frames.push_back(OnivFrame((char*)hdr, HdrSizeWithOnivHdr, nullptr));
        frames.back().append((char*)(buf + common.offset), common.len);
        common.offset += common.len;
    }
    common.len = common.total - common.offset;
    OnivCommon::ConstructEncapHdr(hdr + Layer2HdrSize, OnivCommon::count(),
            frame.SrcIPAddr(), frame.DestIPAddr(),
            htons(OnivGlobal::OnivPort), htons(OnivGlobal::OnivPort),
            OnivCommon::LinearSize() + common.len);
    common.linearization(hdr + EncapHdrSize);
    frames.push_back(OnivFrame((char*)hdr, HdrSizeWithOnivHdr, nullptr));
    frames.back().append((char*)(buf + common.offset), common.len);
}

OnivLnkReq::OnivLnkReq(const char *OnivHdr, size_t OnivSize) : buf(nullptr)
{
    if(OnivSize < OnivCommon::LinearSize()){
        return;
    }

    const uint8_t *p = (uint8_t*)OnivHdr;
    common.structuration(p);
    if(common.type != CastTo16<OnivPacketType>(OnivPacketType::LNK_KA_REQ)){
        return;
    }
    if(common.total != OnivSize - OnivCommon::LinearSize()){
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
    p += signature.structuration(p);

    certs.structuration(p);
}

OnivLnkReq::~OnivLnkReq()
{
    delete[] buf;
}

bool OnivLnkReq::VerifySignature()
{
    return OnivCrypto::VerifySignature(certs.CertChain,
        string((char*)common.UUID, sizeof(common.UUID)),
        signature.data());
}

vector<OnivFrame> OnivLnkReq::request()
{
    return frames;
}

OnivLnkRes::OnivLnkRes(const OnivFrame &frame, const OnivKeyEntry *keyent) : buf(nullptr)
{
    if(!frame.IsLayer4Oniv()){
        return;
    }

    common.type = CastTo16<OnivPacketType>(OnivPacketType::LNK_KA_RES);
    common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
    common.identifier = OnivCommon::count();

    ReqTs = keyent->ts, ResTs = (uint64_t)system_clock::to_time_t(system_clock::now());
    common.total = sizeof(ReqTs) + sizeof(ResTs);

    RmdTp = 1, AppTp = 1;
    common.total += sizeof(RmdTp) + sizeof(AppTp);

    VerifyAlg = keyent->VerifyAlg, KeyAgrAlg = keyent->KeyAgrAlg;
    common.total += sizeof(VerifyAlg) + sizeof(KeyAgrAlg);

    pk.data(keyent->LocalPubKey);
    common.total += pk.LinearSize();

    SigAlg = OnivCrypto::SigAlg();
    signature.data(OnivCrypto::GenSignature(OnivCrypto::UUID() + pk.data())),
    common.total += sizeof(SigAlg) + signature.LinearSize();

    certs.assign(OnivCrypto::CertChain());
    common.total += certs.LinearSize();

    memcpy(common.UUID, OnivCrypto::UUID().c_str(), sizeof(common.UUID));

    // 使用自构建的IP协议封装
    size_t Layer2HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
    size_t EncapHdrSize = Layer2HdrSize + 20 + 8;
    size_t HdrSizeWithOnivHdr = EncapHdrSize + OnivCommon::LinearSize();
    uint8_t hdr[HdrSizeWithOnivHdr] = { 0 };
    memcpy(hdr, frame.SrcHwAddr().c_str(), frame.SrcHwAddr().length());
    memcpy(hdr + frame.SrcHwAddr().length(), frame.DestHwAddr().c_str(), frame.DestHwAddr().length());
    *(uint16_t*)(hdr + 12) = htons(0x0800);

    // 以网络字节序线性化
    buf = new uint8_t[common.total];
    uint8_t *p = buf;

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

    pk.linearization(p);
    p += pk.LinearSize();

    signature.linearization(p);
    p += signature.LinearSize();

    certs.linearization(p);

    // 分片
    common.offset = 0;
    common.len = OnivGlobal::AdapterMTU - HdrSizeWithOnivHdr;
    while(common.offset + common.len < common.total){
        OnivCommon::ConstructEncapHdr(hdr + Layer2HdrSize, OnivCommon::count(),
            frame.DestIPAddr(), frame.SrcIPAddr(),
            frame.DestPort(), frame.SrcPort(),
            OnivCommon::LinearSize() + common.len);
        common.linearization(hdr + EncapHdrSize);
        frames.push_back(OnivFrame((char*)hdr, HdrSizeWithOnivHdr, nullptr));
        frames.back().append((char*)(buf + common.offset), common.len);
        common.offset += common.len;
    }
    common.len = common.total - common.offset;
    OnivCommon::ConstructEncapHdr(hdr + Layer2HdrSize, OnivCommon::count(),
            frame.DestIPAddr(), frame.SrcIPAddr(),
            frame.DestPort(), frame.SrcPort(),
            OnivCommon::LinearSize() + common.len);
    common.linearization(hdr + EncapHdrSize);
    frames.push_back(OnivFrame((char*)hdr, HdrSizeWithOnivHdr, nullptr));
    frames.back().append((char*)(buf + common.offset), common.len);
}

OnivLnkRes::OnivLnkRes(const char *OnivHdr, size_t OnivSize) : buf(nullptr)
{
    if(OnivSize < OnivCommon::LinearSize()){
        return;
    }

    const uint8_t *p = (uint8_t*)OnivHdr;
    common.structuration(p);
    if(common.type != CastTo16<OnivPacketType>(OnivPacketType::LNK_KA_RES)){
        return;
    }
    if(common.total != OnivSize - OnivCommon::LinearSize()){
        return;
    }

    buf = new uint8_t[OnivSize];
    memcpy(buf, OnivHdr, OnivSize);
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

    p += pk.structuration(p);

    p += signature.structuration(p);

    certs.structuration(p);
}

OnivLnkRes::~OnivLnkRes()
{
    delete[] buf;
}

bool OnivLnkRes::VerifySignature()
{
    return OnivCrypto::VerifySignature(certs.CertChain,
        string((char*)common.UUID, sizeof(common.UUID)) + pk.data(),
        signature.data());
}

vector<OnivFrame> OnivLnkRes::response()
{
    return frames;
}

OnivLnkRecord::OnivLnkRecord(const OnivFrame &frame, const OnivKeyEntry *keyent) : buf(nullptr)
{
    if(!frame.IsARP() && !frame.IsIP()){
        return;
    }

    common.type = CastTo16<OnivPacketType>(OnivPacketType::ONIV_RECORD);
    if(keyent->UpdPk){
        common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_SEND);
        UpdTs = (uint64_t)system_clock::to_time_t(system_clock::now());
        KeyAgrAlg = keyent->KeyAgrAlg;
        pk.data(keyent->LocalPubKey);
        common.total = sizeof(UpdTs) + sizeof(KeyAgrAlg) + pk.LinearSize();
    }
    else if(keyent->AckPk){
        common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_SEND);
        UpdTs = keyent->ts;
        AckTs = (uint64_t)system_clock::to_time_t(system_clock::now());
        common.total = sizeof(UpdTs) + sizeof(AckTs);
    }
    else{
        common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
        common.total = 0;
    }
    common.identifier = OnivCommon::count();

    if(frame.IsARP()){
        OriginProtocol = 0x0806;
    }
    else{
        OriginProtocol = 0x0800;
    }
    common.total += sizeof(OriginProtocol);

    VerifyAlg = keyent->VerifyAlg;
    common.total += sizeof(VerifyAlg);

    code.data(string(OnivCrypto::MsgAuchCodeSize(), '\0')); // 占位
    trustee.data(OnivCrypto::GetSubject(keyent->ThirdCert));
    escrow.data(OnivCrypto::GenEscrowData(keyent->ThirdCert, keyent->SessionKey, string()));
    data = frame.OriginUserData(); // data中包含原始的IP首部和四层首部
    common.total += code.LinearSize();
    common.total += trustee.LinearSize();
    common.total += escrow.LinearSize();
    common.total += data.length();

    common.len = common.total;
    common.offset = 0;

    memcpy(common.UUID, OnivCrypto::UUID().c_str(), sizeof(common.UUID));

    // 使用自构建的IP协议封装
    size_t Layer2HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
    size_t EncapHdrSize = Layer2HdrSize + 20 + 8;
    size_t HdrSizeWithOnivHdr = EncapHdrSize + OnivCommon::LinearSize();
    uint8_t hdr[HdrSizeWithOnivHdr] = { 0 };
    memcpy(hdr, frame.Layer2Hdr(), Layer2HdrSize);
    *(uint16_t*)(hdr + 12) = htons(0x0800);
    OnivCommon::ConstructEncapHdr(hdr + Layer2HdrSize, htons(common.identifier),
        frame.SrcIPAddr(), frame.DestIPAddr(),
        htons(OnivGlobal::OnivPort), keyent->RemotePort,
        OnivCommon::LinearSize() + common.total);
    common.linearization(hdr + EncapHdrSize);

    // 以网络字节序线性化
    buf = new uint8_t[common.total];
    uint8_t *p = buf;

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

    *(uint16_t*)p = htons(OriginProtocol);
    p += sizeof(OriginProtocol);

    *(uint16_t*)p = htons(CastTo16<OnivVerifyAlg>(VerifyAlg));
    p += sizeof(VerifyAlg);

    string InitVector(OnivCrypto::UUID()), AssData((char*)hdr + EncapHdrSize, OnivCommon::LinearSize());
    InitVector.append((char*)hdr + EncapHdrSize + 4, 2);
    code.data(OnivCrypto::MsgAuthCode(VerifyAlg, keyent->SessionKey, data, InitVector, AssData));
    code.linearization(p);
    p += code.LinearSize();
    trustee.linearization(p);
    p += trustee.LinearSize();
    escrow.linearization(p);
    p += escrow.LinearSize();

    memcpy(p, data.c_str(), data.length());

    output.append((char*)hdr, HdrSizeWithOnivHdr);
    output.append((char*)buf, common.total);
}

OnivLnkRecord::OnivLnkRecord(const OnivFrame &frame) : buf(nullptr)
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
    if(common.total != OnivSize - OnivCommon::LinearSize()){
        return;
    }

    // TODO
    // 如果覆盖网络支持NAT，则在传输过程中IP首部和传输层首部会发生变化，需要进行修正，现在只修正帧类型
    size_t HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
    uint8_t hdr[HdrSize] = { 0 };
    memcpy(hdr, frame.Layer2Hdr(), HdrSize);
    *(uint16_t*)(hdr + 12) = htons(OriginProtocol);

    buf = new uint8_t[OnivSize];
    memcpy(buf, frame.OnivHdr(), OnivSize);
    p = buf + OnivCommon::LinearSize();

    if((common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_SEND)) != 0){
        UpdTs = *(uint64_t*)p;
        p += sizeof(UpdTs);
        KeyAgrAlg = CastFrom16<OnivKeyAgrAlg>(ntohs(*(uint16_t*)p));
        p += sizeof(KeyAgrAlg);
        p += pk.structuration(p);
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

    p += code.structuration(p);
    p += trustee.structuration(p);
    p += escrow.structuration(p);

    data.assign((char*)p, buf + OnivSize - p);

    output.append((char*)hdr, HdrSize);
    output.append(data.c_str(), data.length());
}

OnivLnkRecord::~OnivLnkRecord()
{
    delete[] buf;
}

bool OnivLnkRecord::VerifyIdentity(const OnivKeyEntry *keyent)
{
    string InitVector(OnivCrypto::UUID()), AssData((char*)buf, OnivCommon::LinearSize());
    InitVector.append((char*)buf + 4, 2);
    return code.data() ==
        OnivCrypto::MsgAuthCode(keyent->VerifyAlg, keyent->SessionKey,
                            data, InitVector, AssData);
}

OnivFrame OnivLnkRecord::record()
{
    return output;
}

OnivFrame OnivLnkRecord::frame()
{
    return output;
}
