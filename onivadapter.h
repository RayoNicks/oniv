#ifndef _ONIV_ADAPTER_H_
#define _ONIV_ADAPTER_H_

#include <cstring>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "onivglobal.h"
#include "onivport.h"

class OnivAdapter : public OnivPort
{
private:
    int FrameFD, CtrlFD;
    bool up;
    string AdapterName;
public:
    OnivAdapter(const string &name, in_addr_t address, uint32_t vni, int AdapterMTU = OnivGlobal::AdapterMTU);
    virtual ~OnivAdapter() override;

    virtual OnivErr send() override;
    virtual OnivErr send(const OnivFrame &frame) override;
    virtual OnivErr recv(OnivFrame &frame) override;

    int handle() const;
    bool IsUp() const;
    const string name() const;
};

#endif
