#ifndef _ONIV_ERR_H_
#define _ONIV_ERR_H_

#include <string>
#include <vector>

using std::string;
using std::vector;

enum OnivErrCode
{
    ERROR_SUCCESSFUL,
    ERROR_CREATE_SERVER_THREAD,
    ERROR_CREATE_SERVER_SOCKET,
    ERROR_REMOVE_SERVER_SOCKET,
    ERROR_BIND_SERVER_SOCKET,
    ERROR_LISTEN_SERVER_SOCKET,
    ERROR_ACCEPT_CONTROLLER_CONNECTION,
    ERROR_READ_CONTROLLER_CMD,
    ERROR_PARSE_CONTROLLER_CMD,
    ERROR_CLOSE_CONTROLLER_CONNECTION,
    ERROR_CREATE_EPOLL_INSTANCE,
    ERROR_WAIT_EPOLL,

    ERROR_UNKNOWN,
};

class OnivErr
{
private:
    static const vector<string> ErrMsgs;
    OnivErrCode Code;
    // string Msg;
    const string& ErrCodeToErrMsg(const OnivErrCode &ec);
public:
    OnivErr() = default;
    OnivErr(const OnivErrCode &ec);
    // OnivErr(const OnivErr &oe);
    // OnivErr(OnivErr &&oe);
    // OnivErr& operator=(const OnivErr &oe);
    // OnivErr& operator=(OnivErr &&oe);
    const OnivErrCode ErrCode();
    const string& ErrMsg();
    bool occured();
};

#endif
