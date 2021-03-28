#ifndef _ONIV_ERR_H_
#define _ONIV_ERR_H_

#include <string>
#include <vector>

using std::string;
using std::vector;

enum OnivErrCode
{
    ERROR_SUCCESSFUL,
    ERROR_BECOME_DAEMMON,
    ERROR_CREATE_TUNNEL_SOCKET,
    ERROR_BIND_TUNNEL_SOCKET,
    ERROR_EPOLL_TUNNEL,

    // server thread error
    ERROR_CREATE_SERVER_THREAD,
    ERROR_CREATE_SERVER_SOCKET,
    ERROR_REMOVE_SERVER_SOCKET,
    ERROR_BIND_SERVER_SOCKET,
    ERROR_LISTEN_SERVER_SOCKET,
    ERROR_ACCEPT_CONTROLLER_CONNECTION,
    ERROR_READ_CONTROLLER_CMD,
    ERROR_PARSE_CONTROLLER_CMD,
    ERROR_CREATE_ADAPTER,
    ERROR_ADAPTER_EXISTS,
    ERROR_UNKNOWN_ADAPTER,
    ERROR_EPOLL_ADAPTER,
    ERROR_CREATE_TUNNEL,
    ERROR_TUNNEL_EXISTS,
    ERROR_ADD_ROUTE,
    ERROR_DEL_ROUTE,
    // adapter thread error
    ERROR_CREATE_ADAPTER_THREAD,
    ERROR_RECV_ADAPTER,
    // tunnel thread error
    ERROR_CREATE_TUNNEL_THREAD,
    ERROR_RECV_TUNNEL,
    // switch error
    ERROR_CREATE_EPOLL_INSTANCE,
    ERROR_WAIT_EPOLL,
    ERROR_NO_FORWARD_ENTRY,
    ERROR_NO_KEY_ENTRY,
    ERROR_NO_FRAGEMENT_ENTRY,
    ERROR_REASSEMBLING_FRAGEMENTS,
    // verification error
    ERROR_WRONG_SIGNATURE,
    ERROR_TUNNEL_VERIFICATION,
    ERROR_LINK_VERIFICATION,

    ERROR_UNKNOWN,
};

class OnivErr
{
private:
    static const vector<string> ErrMsgs;
    OnivErrCode code;
    const string& ErrCodeToErrMsg(const OnivErrCode &ec);
public:
    OnivErr();
    OnivErr(const OnivErrCode &ec);
    const OnivErrCode ErrCode();
    const string& ErrMsg();
    bool occured();
};

#endif
