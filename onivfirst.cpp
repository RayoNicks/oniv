#include "onivfirst.h"
#include "oniventry.h"

void OnivLnkKA::linearization(uint8_t *p)
{
    common.linearization(p), p += OnivCommon::LinearSize();
    *(uint16_t*)p = htons(total), p += sizeof(total);
    *(uint16_t*)p = htons(FrgSize), p += sizeof(FrgSize);
    *(uint16_t*)p = htons(offset), p += sizeof(offset);
}

size_t OnivLnkKA::structuration(const uint8_t *p)
{
    p += common.structuration(p);
    total = ntohs(*(uint16_t*)p), p += sizeof(total);
    FrgSize = ntohs(*(uint16_t*)p), p += sizeof(FrgSize);
    offset = ntohs(*(uint16_t*)p), p += sizeof(offset);
    return LinearSize();
}

size_t OnivLnkKA::LinearSize()
{
    return OnivCommon::LinearSize() +
        sizeof(total) + sizeof(FrgSize) + sizeof(offset);
}

OnivLnkReq::OnivLnkReq(const OnivFrame &frame) : buf(nullptr)
{
    if(!frame.IsARP() && !frame.IsIP()){
        return;
    }

    lka.common.type = CastTo16<OnivPacketType>(OnivPacketType::LNK_KA_REQ);
    lka.common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
    lka.common.identifier = OnivCommon::count();

    tp = system_clock::now();
    lka.total = sizeof(tp);

    PreVerifyAlg = OnivCrypto::LocalAlg<OnivVerifyAlg>();
    SupVerifyAlgSet.insert(OnivCrypto::ListAlg<OnivVerifyAlg>());
    lka.total += sizeof(PreVerifyAlg) + SupVerifyAlgSet.LinearSize();

    PreKeyAgrAlg = OnivCrypto::LocalAlg<OnivKeyAgrAlg>();
    SupKeyAgrAlgSet.insert(OnivCrypto::ListAlg<OnivKeyAgrAlg>());
    lka.total += sizeof(PreKeyAgrAlg) + SupKeyAgrAlgSet.LinearSize();

    SigAlg = OnivCrypto::LocalAlg<OnivSigAlg>();
    signature.data(OnivCrypto::GenSignature(OnivCrypto::UUID()));
    lka.total += sizeof(SigAlg) + signature.LinearSize();

    certs.assign(OnivCrypto::CertChain());
    lka.total += certs.LinearSize();

    memcpy(lka.common.UUID, OnivCrypto::UUID().c_str(), sizeof(lka.common.UUID));

    // 使用自构建的IP协议封装
    size_t Layer2HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
    size_t EncapHdrSize = Layer2HdrSize + 20 + 8;
    size_t HdrSizeWithOnivHdr = EncapHdrSize + OnivLnkKA::LinearSize();
    uint8_t hdr[HdrSizeWithOnivHdr] = { 0 };
    memcpy(hdr, frame.Layer2Hdr(), Layer2HdrSize);
    *(uint16_t*)(hdr + 12) = htons(0x0800);

    // 以网络字节序线性化
    buf = new uint8_t[lka.total];
    uint8_t *p = buf;

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

    // 分片，数据帧进入交换机的时间为请求进入交换机的时间
    lka.offset = 0;
    lka.FrgSize = OnivGlobal::AdapterMaxMTU - HdrSizeWithOnivHdr;
    while(lka.offset + lka.FrgSize < lka.total){
        OnivCommon::ConstructEncapHdr(hdr + Layer2HdrSize, OnivCommon::count(),
            frame.SrcIPAddr(), frame.DestIPAddr(),
            htons(OnivGlobal::OnivPort), htons(OnivGlobal::OnivPort),
            OnivLnkKA::LinearSize() + lka.FrgSize);
        lka.common.len = OnivLnkKA::LinearSize() - OnivCommon::LinearSize() + lka.FrgSize;
        lka.linearization(hdr + EncapHdrSize);
        frames.push_back(OnivFrame((char*)hdr, HdrSizeWithOnivHdr, nullptr, frame.EntryTime()));
        frames.back().append((char*)(buf + lka.offset), lka.FrgSize);
        lka.offset += lka.FrgSize;
    }
    lka.FrgSize = lka.total - lka.offset;
    OnivCommon::ConstructEncapHdr(hdr + Layer2HdrSize, OnivCommon::count(),
            frame.SrcIPAddr(), frame.DestIPAddr(),
            htons(OnivGlobal::OnivPort), htons(OnivGlobal::OnivPort),
            OnivLnkKA::LinearSize() + lka.FrgSize);
    lka.common.len = OnivLnkKA::LinearSize() - OnivCommon::LinearSize() + lka.FrgSize;
    lka.linearization(hdr + EncapHdrSize);
    frames.push_back(OnivFrame((char*)hdr, HdrSizeWithOnivHdr, nullptr, frame.EntryTime()));
    frames.back().append((char*)(buf + lka.offset), lka.FrgSize);
}

OnivLnkReq::OnivLnkReq(const char *OnivHdr, size_t OnivSize) : buf(nullptr)
{
    if(OnivSize < OnivLnkKA::LinearSize()){
        return;
    }

    const uint8_t *p = (uint8_t*)OnivHdr;
    lka.structuration(p);
    if(lka.common.type != CastTo16<OnivPacketType>(OnivPacketType::LNK_KA_REQ)){
        return;
    }
    if(lka.total != OnivSize - OnivLnkKA::LinearSize()){
        return;
    }

    buf = new uint8_t[OnivSize];
    memcpy(buf, OnivHdr, OnivSize);
    p = buf + OnivLnkKA::LinearSize();

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

OnivLnkReq::~OnivLnkReq()
{
    delete[] buf;
}

bool OnivLnkReq::VerifySignature()
{
    return OnivCrypto::VerifySignature(certs.CertChain,
        string((char*)lka.common.UUID, sizeof(lka.common.UUID)),
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

    lka.common.type = CastTo16<OnivPacketType>(OnivPacketType::LNK_KA_RES);
    lka.common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
    lka.common.identifier = OnivCommon::count();

    ReqTp = keyent->tp;
    ResTp = system_clock::now();
    lka.total = sizeof(ReqTp) + sizeof(ResTp);

    RmdTp = 0, AppTp = 1; // 选择根证书作为托管第三方
    lka.total += sizeof(RmdTp) + sizeof(AppTp);

    VerifyAlg = keyent->VerifyAlg, KeyAgrAlg = keyent->KeyAgrAlg;
    lka.total += sizeof(VerifyAlg) + sizeof(KeyAgrAlg);

    pk.data(keyent->LocalPubKey);
    lka.total += pk.LinearSize();

    SigAlg = OnivCrypto::LocalAlg<OnivSigAlg>();
    signature.data(OnivCrypto::GenSignature(OnivCrypto::UUID() + pk.data())),
    lka.total += sizeof(SigAlg) + signature.LinearSize();

    certs.assign(OnivCrypto::CertChain());
    lka.total += certs.LinearSize();

    memcpy(lka.common.UUID, OnivCrypto::UUID().c_str(), sizeof(lka.common.UUID));

    // 使用自构建的IP协议封装
    size_t Layer2HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
    size_t EncapHdrSize = Layer2HdrSize + 20 + 8;
    size_t HdrSizeWithOnivHdr = EncapHdrSize + OnivLnkKA::LinearSize();
    uint8_t hdr[HdrSizeWithOnivHdr] = { 0 };
    memcpy(hdr, frame.SrcHwAddr().c_str(), frame.SrcHwAddr().length());
    memcpy(hdr + frame.SrcHwAddr().length(), frame.DestHwAddr().c_str(), frame.DestHwAddr().length());
    *(uint16_t*)(hdr + 12) = htons(0x0800);

    // 以网络字节序线性化
    buf = new uint8_t[lka.total];
    uint8_t *p = buf;

    *(uint64_t*)p = ReqTp.time_since_epoch().count();
    p += sizeof(ReqTp);
    *(uint64_t*)p = ResTp.time_since_epoch().count();
    p += sizeof(ResTp);

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

    // 分片，请求进入交换机的时间为响应进入交换机的时间
    lka.offset = 0;
    lka.FrgSize = OnivGlobal::AdapterMaxMTU - HdrSizeWithOnivHdr;
    while(lka.offset + lka.FrgSize < lka.total){
        OnivCommon::ConstructEncapHdr(hdr + Layer2HdrSize, OnivCommon::count(),
            frame.DestIPAddr(), frame.SrcIPAddr(),
            frame.DestPort(), frame.SrcPort(),
            OnivLnkKA::LinearSize() + lka.FrgSize);
        lka.common.len = OnivLnkKA::LinearSize() - OnivCommon::LinearSize() + lka.FrgSize;
        lka.linearization(hdr + EncapHdrSize);
        frames.push_back(OnivFrame((char*)hdr, HdrSizeWithOnivHdr, nullptr, frame.EntryTime()));
        frames.back().append((char*)(buf + lka.offset), lka.FrgSize);
        lka.offset += lka.FrgSize;
    }
    lka.FrgSize = lka.total - lka.offset;
    OnivCommon::ConstructEncapHdr(hdr + Layer2HdrSize, OnivCommon::count(),
            frame.DestIPAddr(), frame.SrcIPAddr(),
            frame.DestPort(), frame.SrcPort(),
            OnivLnkKA::LinearSize() + lka.FrgSize);
    lka.common.len = OnivLnkKA::LinearSize() - OnivCommon::LinearSize() + lka.FrgSize;
    lka.linearization(hdr + EncapHdrSize);
    frames.push_back(OnivFrame((char*)hdr, HdrSizeWithOnivHdr, nullptr, frame.EntryTime()));
    frames.back().append((char*)(buf + lka.offset), lka.FrgSize);
}

OnivLnkRes::OnivLnkRes(const char *OnivHdr, size_t OnivSize) : buf(nullptr)
{
    if(OnivSize < OnivLnkKA::LinearSize()){
        return;
    }

    const uint8_t *p = (uint8_t*)OnivHdr;
    lka.structuration(p);
    if(lka.common.type != CastTo16<OnivPacketType>(OnivPacketType::LNK_KA_RES)){
        return;
    }
    if(lka.total != OnivSize - OnivLnkKA::LinearSize()){
        return;
    }

    buf = new uint8_t[OnivSize];
    memcpy(buf, OnivHdr, OnivSize);
    p = buf + OnivLnkKA::LinearSize();

    ReqTp = time_point<system_clock>(system_clock::duration(*(uint64_t*)p));
    p += sizeof(ReqTp);
    ResTp = time_point<system_clock>(system_clock::duration(*(uint64_t*)p));
    p += sizeof(ResTp);

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
        string((char*)lka.common.UUID, sizeof(lka.common.UUID)) + pk.data(),
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
    common.identifier = OnivCommon::count();

    if(keyent->UpdPk){
        common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_PK);
        UpdTp = system_clock::now();
        KeyAgrAlg = keyent->KeyAgrAlg;
        pk.data(keyent->LocalPubKey);
        common.len = sizeof(UpdTp) + sizeof(KeyAgrAlg) + pk.LinearSize();
    }
    else if(keyent->AckPk){
        common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_PK);
        UpdTp = keyent->tp;
        AckTp = system_clock::now();
        common.len = sizeof(UpdTp) + sizeof(AckTp);
    }
    else{
        common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
        common.len = 0;
    }

    if(frame.IsARP()){
        OriginProtocol = 0x0806;
    }
    else{
        OriginProtocol = 0x0800;
    }
    common.len += sizeof(OriginProtocol);

    VerifyAlg = keyent->VerifyAlg;
    common.len += sizeof(VerifyAlg);

    code.data(string(OnivCrypto::MsgAuthCodeSize(), '\0')); // 占位
    trustee.data(OnivCrypto::GetSubject(keyent->ThirdCert));
    escrow.data(OnivCrypto::GenEscrowData(keyent->ThirdCert, keyent->SessionKey, string()));
    data = frame.OriginUserData(); // data中包含原始的IP首部和四层首部
    common.len += code.LinearSize() + trustee.LinearSize() + escrow.LinearSize();
    common.len += data.length();

    memcpy(common.UUID, OnivCrypto::UUID().c_str(), sizeof(common.UUID));

    // 使用自构建的IP协议封装
    size_t Layer2HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
    size_t EncapHdrSize = Layer2HdrSize + 20 + 8;
    size_t HdrSizeWithOnivHdr = EncapHdrSize + OnivCommon::LinearSize();
    uint8_t hdr[HdrSizeWithOnivHdr] = { 0 };
    memcpy(hdr, frame.Layer2Hdr(), Layer2HdrSize);
    *(uint16_t*)(hdr + 12) = htons(0x0800);
    OnivCommon::ConstructEncapHdr(hdr + Layer2HdrSize, OnivCommon::count(),
        frame.SrcIPAddr(), frame.DestIPAddr(),
        htons(OnivGlobal::OnivPort), keyent->RemoteAddress.sin_port,
        OnivCommon::LinearSize() + common.len);
    common.linearization(hdr + EncapHdrSize);

    // 以网络字节序线性化
    buf = new uint8_t[common.len];
    uint8_t *p = buf;

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

    *(uint16_t*)p = htons(OriginProtocol);
    p += sizeof(OriginProtocol);

    *(uint16_t*)p = htons(CastTo16<OnivVerifyAlg>(VerifyAlg));
    p += sizeof(VerifyAlg);

    string AssData((char*)hdr + EncapHdrSize, OnivCommon::LinearSize());
    string InitVector((char*)common.UUID, sizeof(common.UUID));
    InitVector.append((char*)hdr + EncapHdrSize + 4, 2); // identifier
    code.data(OnivCrypto::MsgAuthCode(VerifyAlg, keyent->SessionKey, data, InitVector, AssData));
    code.linearization(p);
    p += code.LinearSize();
    trustee.linearization(p);
    p += trustee.LinearSize();
    escrow.linearization(p);
    p += escrow.LinearSize();

    memcpy(p, data.c_str(), data.length());

    output = OnivFrame((char*)hdr, HdrSizeWithOnivHdr, frame.IngressPort(), frame.EntryTime());
    output.append((char*)buf, common.len);
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
    if(common.len != OnivSize - OnivCommon::LinearSize()){
        return;
    }

    buf = new uint8_t[OnivSize];
    memcpy(buf, frame.OnivHdr(), OnivSize);
    p = buf + OnivCommon::LinearSize();

    if((common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_PK)) != 0){
        UpdTp = time_point<system_clock>(system_clock::duration(*(uint64_t*)p));;
        p += sizeof(UpdTp);
        KeyAgrAlg = CastFrom16<OnivKeyAgrAlg>(ntohs(*(uint16_t*)p));
        p += sizeof(KeyAgrAlg);
        p += pk.structuration(p);
    }
    else if((common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_PK)) != 0){
        UpdTp = time_point<system_clock>(system_clock::duration(*(uint64_t*)p));;
        p += sizeof(UpdTp);
        AckTp = time_point<system_clock>(system_clock::duration(*(uint64_t*)p));;
        p += sizeof(AckTp);
    }

    OriginProtocol = ntohs(*(uint16_t*)p);
    p += sizeof(OriginProtocol);

    VerifyAlg = CastFrom16<OnivVerifyAlg>(ntohs(*(uint16_t*)p));
    p += sizeof(VerifyAlg);

    p += code.structuration(p);
    p += trustee.structuration(p);
    p += escrow.structuration(p);

    data.assign((char*)p, buf + OnivSize - p);

    // TODO
    // 如果覆盖网络支持NAT，则在传输过程中IP首部和传输层首部会发生变化，需要进行修正，现在只修正帧类型即可
    size_t HdrSize = frame.Layer3Hdr() - frame.Layer2Hdr();
    uint8_t hdr[HdrSize] = { 0 };
    memcpy(hdr, frame.Layer2Hdr(), HdrSize);
    *(uint16_t*)(hdr + 12) = htons(OriginProtocol);
    output = OnivFrame((char*)hdr, HdrSize, frame.IngressPort(), frame.EntryTime());
    output.append(data.c_str(), data.length());
}

OnivLnkRecord::~OnivLnkRecord()
{
    delete[] buf;
}

bool OnivLnkRecord::VerifyIdentity(const OnivKeyEntry *keyent)
{
    string AssData((char*)buf, OnivCommon::LinearSize());
    string InitVector((char*)common.UUID, sizeof(common.UUID));
    InitVector.append((char*)buf + 4, 2); // identifier
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
