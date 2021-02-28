#include "onivframe.h"
#include "onivadapter.h"
#include "onivpacket.h"
#include "onivtunnel.h"

OnivFrame::OnivFrame() : ingress(nullptr)
{

}

OnivFrame::OnivFrame(const OnivFrame &of) : frame(of.frame), ingress(of.ingress)
{

}

OnivFrame::OnivFrame(OnivFrame &&of) : frame(of.frame), ingress(of.ingress)
{

}

OnivFrame& OnivFrame::operator=(const OnivFrame &of)
{
    this->frame = of.frame;
    ingress = of.ingress;
    return *this;
}

OnivFrame& OnivFrame::operator=(OnivFrame &&of)
{
    this->frame = of.frame;
    ingress = of.ingress;
    return *this;
}

OnivFrame::~OnivFrame()
{

}

OnivFrame::OnivFrame(const char *buf, const size_t size, OnivPort *port)
    : frame(buf, size), ingress(port)
{

}
/*
OnivFrame::OnivFrame(const OnivPacket &packet)
    : frame(packet.frame(), packet.size() - packet.HdrSize()), ingress(packet.IngressPort())
{

}
*/
void OnivFrame::dump() const
{
    for(size_t i = 0; i < frame.size(); i += 16)
    {
        for(size_t j = 0; j < 16 && i + j < frame.size(); j++)
        {
            cout << hex << setw(2) << setfill('0') << (frame[i + j] & 0xff) << ' ';
        }
        cout << '\n';
    }
    cout << '\n';
}
/*
vector<OnivFrame> OnivFrame::encapsulate(const string &LnkSK, OnivVerifyAlg VerifyAlg)
{
    vector<OnivFrame> frames;
    if(IsARP()){
        string UserData = frame.substr(Layer3Hdr() - Layer2Hdr());

    }
    else if(IsIP()){
        ;
    }

    return frames;
}

void OnivFrame::decapsulate(const string &LnkSK, OnivVerifyAlg VerifyAlg)
{
    ;
}
*/
OnivPort* OnivFrame::IngressPort() const
{
    return ingress;
}

bool OnivFrame::empty() const
{
    return frame.empty();
}

size_t OnivFrame::size() const
{
    return frame.length();
}

OnivPacketType OnivFrame::type() const
{
    return static_cast<OnivPacketType>(ntohs(((OnivCommon*)OnivHdr())->type));
}

const char* OnivFrame::buffer() const
{
    return frame.c_str();
}

const char* OnivFrame::Layer2Hdr() const
{
    return buffer();
}

const char* OnivFrame::Layer3Hdr() const
{
    if(IsARP() || IsIP() || IsLayer3Oniv()){
        return Layer2Hdr() + 14;
    }
    else{
        return nullptr;
    }
}

const char* OnivFrame::Layer4Hdr() const
{
    if(IsIP()){
        return Layer3Hdr() + IPHdrLen();
    }
    else{
        return nullptr;
    }
}

const char* OnivFrame::TCPHdr() const
{
    return Layer4Hdr();
}

const char* OnivFrame::UDPHdr() const
{
    return Layer4Hdr();
}

const string OnivFrame::UserData() const
{
    const char *p;
    if(IsARP()){
        p = Layer3Hdr();
        return string(p, buffer() + size() - p);
    }
    else if(IsIP()){
        p = Layer4Hdr();
        return string(p, buffer() + size() - p);
    }
    else{
        return string();
    }
}
/*
const char* OnivFrame::UserData() const
{
    if(IsLayer3Oniv()){
        return nullptr;
    }
    else if(IsLayer4Oniv()){
        return nullptr;
    }
    else if(IsARP()){
        return Layer3Hdr();
    }
    else if(IsIP()){
        return Layer4Hdr();
    }
    else{
        return nullptr;
    }
}

size_t OnivFrame::UserDataSize() const
{
    const char *p = UserData();
    if(p != nullptr){
        return buffer() + size() - p;
    }
    else{
        return 0;
    }
}
*/
const char* OnivFrame::OnivHdr() const
{
    if(IsLayer3Oniv()){
        return Layer3Hdr();
    }
    else if(IsLayer4Oniv()){
        return Layer4Hdr() + 8; // 8字节UDP首部
    }
    else{
        return nullptr;
    }
}

bool OnivFrame::IsLayer3Oniv() const
{
    return ntohs(*(u_int16_t*)(buffer() + 12)) == OnivGlobal::OnivType;
}

bool OnivFrame::IsLayer4Oniv() const
{
    return IsUDP() && (SrcPort() == htons(OnivGlobal::TunnelPortNo) || DestPort() == htons(OnivGlobal::TunnelPortNo));
}

bool OnivFrame::IsOniv() const
{
    return IsLayer3Oniv() || IsLayer4Oniv();
}

uint8_t OnivFrame::Layer4Protocol() const
{
    if(IsICMP()){
        return 0x01;
    }
    else if(IsTCP()){
        return 0x06;
    }
    else if(IsUDP()){
        return 0x11;
    }
    else{
        return 0;
    }
}

const string OnivFrame::DestHwAddr() const
{
    return string(Layer2Hdr(), 6);
}

const string OnivFrame::SrcHwAddr() const
{
    return string(Layer2Hdr() + 6, 6);
}

bool OnivFrame::IsBroadcast() const
{
    return DestHwAddr() == string(6, 0xFF);
}

bool OnivFrame::IsARP() const
{
    return ntohs(*(u_int16_t*)(buffer() + 12)) == 0x0806;
}

bool OnivFrame::IsIP() const
{
    return ntohs(*(u_int16_t*)(buffer() + 12)) == 0x0800;
}

uint8_t OnivFrame::IPHdrLen() const
{
    return (*Layer3Hdr() & 0x0F) * 4;
}

in_addr_t OnivFrame::SrcIPAddr() const
{
    if(IsARP()){
        return *(in_addr_t*)(Layer3Hdr() + 14);
    }
    else if(IsIP()){
        return *(in_addr_t*)(Layer3Hdr() + 12);
    }
    else{
        return 0;
    }
}

in_addr_t OnivFrame::DestIPAddr() const
{
    if(IsARP()){
        return *(in_addr_t*)(Layer3Hdr() + 24);
    }
    else if(IsIP()){
        return *(in_addr_t*)(Layer3Hdr() + 16);
    }
    else{
        return 0;
    }
}

bool OnivFrame::IsICMP() const
{
    return IsIP() && *(Layer3Hdr() + 9) == 0x01;
}

bool OnivFrame::IsTCP() const
{
    return IsIP() && *(Layer3Hdr() + 9) == 0x06;
}

bool OnivFrame::IsUDP() const
{
    return IsIP() && *(Layer3Hdr() + 9) == 0x11;
}

in_port_t OnivFrame::SrcPort() const
{
    if(IsTCP() || IsUDP()){
        return *(in_port_t*)Layer4Hdr();
    }
    else{
        return 0;
    }
}

in_port_t OnivFrame::DestPort() const
{
    if(IsTCP() || IsUDP()){
        return *(in_port_t*)(Layer4Hdr() + 2);
    }
    else{
        return 0;
    }
}

void OnivFrame::reverse()
{
    size_t offset = 0;
    for(size_t i = 0; i < 6; i++)
    {
        swap(frame[offset + i], frame[offset + i + 6]);
    }
    if(IsIP()){
        offset = 14 + 12;
        for(size_t i = 0; i < 4; i++)
        {
            swap(frame[offset + i], frame[offset + i + 4]);
        }
        if(IsUDP()){
            offset = 14 + IPHdrLen();
            for(size_t i = 0; i < 2; i++)
            {
                swap(frame[offset + i], frame[offset + i + 2]);
            }
        }
    }
}
