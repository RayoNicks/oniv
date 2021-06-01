#ifndef _ONIV_ADAPTER_H_
#define _ONIV_ADAPTER_H_

#include <string>

#include <netinet/in.h>

#include "onivport.h"

class OnivAdapter : public OnivPort
{
private:
    int fd, ctrl;
    bool up;
    std::string AdapterName;
    in_addr_t addr, NetMask;
    std::string HwAddr;
public:
    OnivAdapter(const std::string &name, in_addr_t address, in_addr_t mask, uint32_t bdi, int mtu);
    OnivAdapter() = delete;
    OnivAdapter(const OnivAdapter &adapter) = delete;
    OnivAdapter& operator=(const OnivAdapter &adapter) = delete;
    virtual ~OnivAdapter() override;

    virtual OnivErr send() override;
    OnivErr recv(OnivFrame &frame);

    int handle() const;
    bool IsUp() const;
    const std::string name() const;
    in_addr_t address() const;
    const std::string MAC() const;
};

#endif
