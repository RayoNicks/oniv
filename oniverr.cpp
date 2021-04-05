#include "oniverr.h"

OnivErr::OnivErr() : code(OnivErrCode::ERROR_SUCCESSFUL)
{

}

OnivErr::OnivErr(const OnivErrCode &ec) : code(ec)
{

}

const string& OnivErr::ErrCodeToErrMsg(const OnivErrCode &ec)
{
    if(ec >= OnivErrCode::ERROR_UNKNOWN) return ErrMsgs.back();
    else return ErrMsgs[static_cast<vector<string>::size_type>(ec)];
}

const OnivErrCode OnivErr::ErrCode()
{
    return code;
}

const string& OnivErr::ErrMsg()
{
    return ErrCodeToErrMsg(code);
}

bool OnivErr::occured()
{
    return code != OnivErrCode::ERROR_SUCCESSFUL;
}

const vector<string> OnivErr::ErrMsgs = {
    "Successful",
    "Become daemon error",
    "Create tunnel socket failed",
    "Bind tunnel socket failed",
    "Add tunnel to epoll failed",
    // server message
    "Create server thread failed",
    "Create server socket failed",
    "Remove server socket file failed",
    "Bind server socket failed",
    "Listen on server socket failed",
    "Accept controller connection failed",
    "Read controller command failed",
    "Parse controller command failed",
    "Write back to controller failed",
    "Create adapter failed",
    "Adapter exists",
    "Unknown adapter",
    "Epoll adapter failed",
    "Create tunnel interface failed",
    "Tunnel exists",
    "Add route failed",
    "Delete route failed",
    // adapter thread error
    "Create adapter thread failed",
    "Receive frame from adapter failed",
    // tunnel thread error
    "Create tunnel thread failed",
    "Receive packet from tunnel failed",
    // egress thread error
    "Send frame to adapter failed",
    // switch message
    "Create epoll instance failed",
    "Wait epoll failed",
    "Can't not find forwarding entry",
    "Can't find key entry",
    "No corresponding fragement entry",
    "Reassembling link fragements",
    // verification error
    "Verify signature failed",
    "Tunnel verification failed",
    "Link verification failed",

    "Unknown error",
};
