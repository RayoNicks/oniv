#include "oniverr.h"

OnivErr::OnivErr(const OnivErrCode &ec) : Code(ec)// , Msg(ErrCodeToErrMsg(ec))
{

}

// OnivErr::OnivErr(const OnivErr &oe)
// {
//     Code = oe.Code;
// }

// OnivErr::OnivErr(OnivErr &&oe)
// {
//     Code = oe.Code;
// }

// OnivErr& OnivErr::operator=(const OnivErr &oe)
// {
//     Code = oe.Code;
//     // Msg = oe.Msg;
// }

// OnivErr& OnivErr::operator=(OnivErr &&oe)
// {
//     Code = oe.Code;
//     // Msg = oe.Msg;
// }

const string& OnivErr::ErrCodeToErrMsg(const OnivErrCode &ec)
{
    if(ec >= OnivErrCode::ERROR_UNKNOWN) return ErrMsgs.back();
    else return ErrMsgs[static_cast<vector<string>::size_type>(ec)];
}

const OnivErrCode OnivErr::ErrCode()
{
    return Code;
}

const string& OnivErr::ErrMsg()
{
    return ErrCodeToErrMsg(Code);
}

bool OnivErr::occured()
{
    return Code != OnivErrCode::ERROR_SUCCESSFUL;
}

const vector<string> OnivErr::ErrMsgs = {
    "Successful",
    "Create server thread failed",
    "Create server socket failed",
    "Remove server socket file failed",
    "Bind server socket failed",
    "Listen on server socket failed",
    "Accept controller connection failed",
    "Read controller command failed",
    "Parse controller command",
    "Close controller connection failed",
    "Create epoll instance failed",
    "Wait epoll failed",

    "Unknown error",
};
