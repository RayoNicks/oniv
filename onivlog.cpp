#include "onivlog.h"

using std::chrono::duration_cast;
using std::chrono::microseconds;
using std::chrono::milliseconds;
using std::chrono::system_clock;
using std::hex;
using std::ostringstream;
using std::setfill;
using std::setw;

char* OnivLog::Net2Asc(in_addr_t address)
{
    return inet_ntoa(in_addr{ address });
}

string OnivLog::Str2Hex(const string &str)
{
    ostringstream oss;
    oss << hex << setw(2) << setfill('0');
    for(const char c : str)
    {
        oss << (c & 0xFF);
    }
    return oss.str();
}

string OnivLog::Str2Hex(const char *p, size_t len)
{
    ostringstream oss;
    oss << hex << setw(2) << setfill('0');
    for(size_t i = 0; i < len; i++)
    {
        oss << (p[i]& 0xFF);
    }
    return oss.str();
}

void OnivLog::InitLogSystem()
{
    openlog("onivd", LOG_PID | LOG_NDELAY, LOG_USER);
}

void OnivLog::ExitLogSystem()
{
    closelog();
}

void OnivLog::log(const string &log, int priority)
{
    syslog(priority, "%s", log.c_str());
}

void OnivLog::LogOnivErr(OnivErr oe)
{
    if(oe.occured()){
        syslog(LOG_ERR, "%s", oe.ErrMsg().c_str());
    }
}

void OnivLog::LogFrameLatency(const OnivFrame &frame)
{
    ostringstream oss;
    time_point<system_clock> entry = frame.EntryTime();
    time_point<system_clock> leave = system_clock::now();

    if(frame.IsARP()){
        oss << "ARP:";
        if(*(frame.Layer3Hdr() + 7) == 0x01){
            oss << "Request, ";
        }
        else if(*(frame.Layer3Hdr() + 7) == 0x02){
            oss << "Response, ";
        }
        else{
            oss << "Unknown type, ";
        }
        oss << "(SMac, SIP)=(" << Str2Hex(frame.SrcHwAddr()) << ", " << Net2Asc(frame.SrcIPAddr()) << "), ";
        oss << "(DMac, DIP)=(" << Str2Hex(frame.DestHwAddr()) << ", " << Net2Asc(frame.DestIPAddr()) << "), ";
    }
    else{
        if(frame.IsLayer4Oniv()){
            oss << "ONIV:";
            switch (frame.type())
            {
            case OnivPacketType::LNK_KA_REQ:
                oss << "Link Request, ";
                break;
            case OnivPacketType::LNK_KA_RES:
                oss << "Link Response, ";
                break;
            case OnivPacketType::ONIV_RECORD:
                oss << "Link Record, ";
                break;
            default:
                oss << "Other type, ";
                break;
            }
        }
        else if(frame.IsUDP()){
            oss << "UDP:";
            oss << "SPort=" << ntohs(frame.SrcPort()) << ", ";
            oss << "DPort=" << ntohs(frame.DestPort()) << ", ";
        }
        else if(frame.IsTCP()){
            oss << "TCP:";
            oss << "SPort=" << ntohs(frame.SrcPort()) << ", ";
            oss << "DPort=" << ntohs(frame.DestPort()) << ", ";
        }
        else if(frame.IsICMP()){
            oss << "ICMP:";
            switch (*frame.Layer4Hdr())
            {
            case 0x08:
                oss << "Echo Request, ";
                break;
            case 0x00:
                oss << "Echo Response, ";
                break;
            default:
                oss << "Other type, ";
                break;
            }
        }
        else{
            return;
        }
        oss << "SIP=" << Net2Asc(frame.SrcIPAddr()) << ", ";
        oss << "DIP=" << Net2Asc(frame.DestIPAddr()) << ", ";
    }

    // oss << "entry time: " << entry.time_since_epoch().count() << ", ";
    // oss << "leave time: " << leave.time_since_epoch().count() << ", ";
    oss << "latency=" << duration_cast<microseconds>((leave - entry)).count() << "(us)";

    syslog(LOG_INFO, "%s", oss.str().c_str());
}

void OnivLog::LogLnkReq(in_addr_t address)
{
    syslog(LOG_NOTICE, "Link key agreement request to %s", inet_ntoa(in_addr{address}));
}

void OnivLog::LogLnkReq(const OnivKeyEntry &keyent)
{
    ostringstream oss("Link key agreement request from ", ostringstream::ate);

    oss << OnivCrypto::GetSubject(keyent.RemoteCert) << ", ";
    oss << "UUID=" << Str2Hex(keyent.RemoteUUID);

    syslog(LOG_NOTICE, "%s", oss.str().c_str());
}

void OnivLog::LogTunReq(const OnivKeyEntry &keyent)
{
    ostringstream oss("Tunnel key agreement request", ostringstream::ate);

    if(keyent.RemoteUUID.empty()){
        oss << " to " << inet_ntoa(keyent.RemoteAddress.sin_addr);
    }
    else{
        oss << " from " << OnivCrypto::GetSubject(keyent.RemoteCert) << ", ";
        oss << "UUID=" << Str2Hex(keyent.RemoteUUID);
    }

    syslog(LOG_NOTICE, "%s", oss.str().c_str());
}

void OnivLog::LogRes(const OnivKeyEntry &keyent, OnivKeyAgrType type)
{
    ostringstream oss(type == OnivKeyAgrType::LNK_KA ? "Link" : "Tunnel", ostringstream::ate);
    time_point<system_clock> now = system_clock::now();
    bool SOR = keyent.SessionKey.empty();

    oss << " key agreement response";
    if(SOR){
        oss << " to ";
    }
    else{
        oss << " from ";
    }
    oss << OnivCrypto::GetSubject(keyent.RemoteCert) << ", ";
    oss << "UUID=" << Str2Hex(keyent.RemoteUUID) << ", ";
    oss << "verification algorithm=" << OnivCrypto::ConvAlgNum<OnivVerifyAlg>(keyent.VerifyAlg) << ", ";
    oss << "key agreement algorithm=" << OnivCrypto::ConvAlgNum<OnivKeyAgrAlg>(keyent.KeyAgrAlg) << ", ";

    if(!SOR){
        oss << "RTT for ";
        oss << (type == OnivKeyAgrType::LNK_KA ? "link" : "tunnel");
        oss << " key agreement=" << duration_cast<milliseconds>(now - keyent.tp).count() << "(ms)";
    }

    syslog(LOG_NOTICE, "%s", oss.str().c_str());
}

void OnivLog::LogUpd(const OnivKeyEntry &keyent, OnivKeyAgrType type)
{
    ostringstream oss(type == OnivKeyAgrType::LNK_KA ? "Link" : "Tunnel", ostringstream::ate);

    oss << " key agreement update message";
    if(keyent.UpdPk){
        oss << " to ";
    }
    else{
        oss << " from ";
    }
    oss << "UUID=" << Str2Hex(keyent.RemoteUUID);

    syslog(LOG_NOTICE, "%s", oss.str().c_str());
}

void OnivLog::LogAck(const OnivKeyEntry &keyent, OnivKeyAgrType type)
{
    ostringstream oss(type == OnivKeyAgrType::LNK_KA ? "Link" : "Tunnel", ostringstream::ate);

    oss << " key agreement acknowledgement message";

    if(keyent.AckPk){
        oss << " to ";
    }
    else{
        oss << " from ";
    }
    oss << "UUID=" << Str2Hex(keyent.RemoteUUID);

    syslog(LOG_NOTICE, "%s", oss.str().c_str());
}
