#include "onivframe.h"
#include "onivadapter.h"
#include "onivpacket.h"
#include "onivtunnel.h"

const char* OnivFrame::Layer3Hdr() const
{
    return frame.c_str() + 14;
}

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

OnivFrame::OnivFrame(const OnivPacket &op)
    : frame(op.frame(), op.size() - op.HdrSize()), ingress(op.IngressPort())
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

const char* OnivFrame::data() const
{
    return frame.c_str();
}

const char* OnivFrame::DestHwAddr() const
{
    return frame.c_str();
}

const char* OnivFrame::SrcHwAddr() const
{
    return frame.c_str() + 6;
}

bool OnivFrame::IsBroadcast()
{
    return string(DestHwAddr(), 6) == string(6, 0xFF);
}

bool OnivFrame::ARP() const
{
    return *(u_int16_t*)(data() + 12) == htons(0x0806);
}

bool OnivFrame::IP() const
{
    return *(u_int16_t*)(data() + 12) == htons(0x0800);
}

in_addr_t OnivFrame::SrcIPAddr() const
{
    if(IP()){
        return *(in_addr_t*)(Layer3Hdr() + 12);
    }
    else return 0;
}

in_addr_t OnivFrame::DestIPAddr() const
{
    if(IP()){
        return *(in_addr_t*)(Layer3Hdr() + 16);
    }
    else return 0;
}

bool OnivFrame::TCP() const
{
    // TODO
    return false;
}

bool OnivFrame::UDP() const
{
    // TODO
    return false;
}
