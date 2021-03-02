#ifndef _ONIV_ADAPTER_H_
#define _ONIV_ADAPTER_H_

#include <cstring>

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
    int fd, ctrl;
    bool up;
    string AdapterName;
    in_addr_t addr, NetMask;
    string HwAddr;
public:
    OnivAdapter(const string &name, in_addr_t address, in_addr_t mask, uint32_t vni, int mtu);
    OnivAdapter() = delete;
    OnivAdapter(const OnivAdapter &adapter) = delete;
    OnivAdapter& operator=(const OnivAdapter &adapter) = delete;
    virtual ~OnivAdapter() override;

    virtual OnivErr send() override;
    OnivErr recv(OnivFrame &frame);

    int handle() const;
    bool IsUp() const;
    const string name() const;
    in_addr_t address() const;
    const string MAC() const;
};

#endif
