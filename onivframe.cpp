#include "onivframe.h"

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
    return CastFrom16<OnivPacketType>(ntohs(((OnivCommon*)OnivHdr())->type));
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
    if(IsARP() || IsIP()){
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

const string OnivFrame::OriginUserData() const
{
    if(IsARP() || IsIP()){
        const char *p = Layer3Hdr();
        return string(Layer3Hdr(), buffer() + size() - p);
    }
    else{
        return string();
    }
}

const char* OnivFrame::OnivHdr() const
{
    if(IsLayer4Oniv()){
        return Layer4Hdr() + 8; // 8字节UDP首部
    }
    else return nullptr;
}

bool OnivFrame::IsLayer4Oniv() const
{
    return IsUDP() && (SrcPort() == htons(OnivGlobal::TunnelPortNo) || DestPort() == htons(OnivGlobal::TunnelPortNo));
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
