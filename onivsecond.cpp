#include "onivsecond.h"

OnivTunReq::OnivTunReq(uint32_t vni) : buf(nullptr)
{
    common.type = CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_REQ);
    common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
    common.identifier = OnivCommon::count();

    bdi = vni;
    common.total = sizeof(bdi);

    ts = (uint64_t)system_clock::to_time_t(system_clock::now());
    common.total += sizeof(ts);

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

    common.len = common.total;
    common.offset = 0;

    memcpy(common.UUID, OnivCrypto::UUID().c_str(), sizeof(common.UUID));

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
    p += SupKeyAgrAlgSet.LinearSize();

    *(uint16_t*)p = htons(CastTo16<OnivSigAlg>(SigAlg));
    p += sizeof(SigAlg);
    signature.linearization(p);
    p += signature.LinearSize();

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
    if(common.total != packet.size() - OnivCommon::LinearSize()){
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
        string((char*)common.UUID, sizeof(common.UUID)),
        signature.data());
}

const char* OnivTunReq::request()
{
    return (const char*)buf;
}

size_t OnivTunReq::size()
{
    return OnivCommon::LinearSize() + common.total;
}

OnivTunRes::OnivTunRes(uint32_t vni, const OnivKeyEntry *keyent) : buf(nullptr)
{
    common.type = CastTo16<OnivPacketType>(OnivPacketType::TUN_KA_RES);
    common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
    common.identifier = OnivCommon::count();

    bdi = vni;
    common.total = sizeof(bdi);

    ReqTs = keyent->ts, ResTs = (uint64_t)system_clock::to_time_t(system_clock::now());
    common.total += sizeof(ReqTs) + sizeof(ResTs);

    VerifyAlg = keyent->VerifyAlg, KeyAgrAlg = keyent->KeyAgrAlg;
    common.total += sizeof(VerifyAlg) + sizeof(KeyAgrAlg);

    pk.data(OnivCrypto::AcqPubKey(KeyAgrAlg));
    common.total += pk.LinearSize();

    SigAlg = OnivCrypto::SigAlg();
    signature.data(OnivCrypto::GenSignature(OnivCrypto::UUID() + pk.data()));
    common.total += sizeof(SigAlg) + signature.LinearSize();

    certs.assign(OnivCrypto::CertChain());
    common.total += certs.LinearSize();

    common.len = common.total;
    common.offset = 0;

    memcpy(common.UUID, OnivCrypto::UUID().c_str(), sizeof(common.UUID));

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

    pk.linearization(p);
    p += pk.LinearSize();

    signature.linearization(p);
    p += signature.LinearSize();

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
    if(common.total != packet.size() - OnivCommon::LinearSize()){
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
        string((char*)common.UUID, sizeof(common.UUID)) + pk.data(),
        signature.data());
}

const char* OnivTunRes::response()
{
    return (const char*)buf;
}

size_t OnivTunRes::size()
{
    return OnivCommon::LinearSize() + common.total;
}

OnivTunRecord::OnivTunRecord(uint32_t vni, const OnivFrame &frame, const OnivKeyEntry *keyent) : buf(nullptr)
{
    common.type = CastTo16<OnivPacketType>(OnivPacketType::ONIV_RECORD);

    bdi = vni;
    common.total = sizeof(bdi);

    if(keyent->UpdPk){
        common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::UPD_SEND);
        UpdTs = (uint64_t)system_clock::to_time_t(system_clock::now());
        KeyAgrAlg = keyent->KeyAgrAlg;
        pk.data(keyent->LocalPubKey);
        common.total += sizeof(UpdTs) + sizeof(KeyAgrAlg) + pk.LinearSize();
    }
    else if(keyent->AckPk){
        common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_SEND);
        UpdTs = keyent->ts;
        AckTs = (uint64_t)system_clock::to_time_t(system_clock::now());
        common.total += sizeof(UpdTs) + sizeof(AckTs);
    }
    else{
        common.flag = CastTo16<OnivPacketFlag>(OnivPacketFlag::NONE);
        common.total += 0;
    }
    common.identifier = OnivCommon::count();

    VerifyAlg = keyent->VerifyAlg;
    common.total += sizeof(VerifyAlg);

    code.data(string(OnivCrypto::MsgAuchCodeSize(), '\0')); // 占位
    data.assign(frame.buffer(), frame.size());
    common.total += code.LinearSize();
    common.total += data.length();

    common.len = common.total;
    common.offset = 0;

    memcpy(common.UUID, OnivCrypto::UUID().c_str(), sizeof(common.UUID));

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

    string AssData((char*)buf, OnivCommon::LinearSize());
    string InitVector((char*)common.UUID, sizeof(common.UUID));
    InitVector.append((char*)buf + 4, 2);
    code.data(OnivCrypto::MsgAuthCode(VerifyAlg, keyent->SessionKey, data, InitVector, AssData));
    code.linearization(p);
    p += code.LinearSize();

    memcpy(p, data.c_str(), data.length());
    cout << "\nSession Key is: ";
    for(const char &c : keyent->SessionKey)
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << "\nInit Vector is: ";
    for(const char &c : InitVector)
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << "\nAss Data is: ";
    for(const char &c : AssData)
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
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
    if(common.total != packet.size() - OnivCommon::LinearSize()){
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
        p += pk.structuration(p);
    }
    else if((common.flag & CastTo16<OnivPacketFlag>(OnivPacketFlag::ACK_SEND)) != 0){
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
    string AssData((char*)buf, OnivCommon::LinearSize());
    string InitVector((char*)common.UUID, sizeof(common.UUID));
    InitVector.append((char*)buf + 4, 2);
    cout << "\nSession Key is: ";
    for(const char &c : keyent->SessionKey)
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << "\nInit Vector is: ";
    for(const char &c : InitVector)
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    cout << "\nAss Data is: ";
    for(const char &c : AssData)
    {
        cout << hex << setw(2) << setfill('0') << (c & 0xFF) << ' ';
    }
    return code.data() ==
        OnivCrypto::MsgAuthCode(keyent->VerifyAlg, keyent->SessionKey,
                            data, InitVector, AssData);
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
    return OnivCommon::LinearSize() + common.total;
}

size_t OnivTunRecord::FrameSize()
{
    return data.length();
}
