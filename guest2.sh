#! /bin/bash
set -x

# 添加网卡作为网关
sudo ./onivctl add-adp onivgw1 172.16.1.1 255.255.255.0 1000 1300
sudo ./onivctl add-adp onivgw3 172.16.3.1 255.255.255.0 3000 1300
sudo ./onivctl add-adp onivgw4 172.16.4.1 255.255.255.0 4000 1300

# 添加到客户机3的隧道
# sudo ./onivctl add-tun 192.168.11.130 3000

# 添加到云服务器的隧道
sudo ./onivctl add-tun 42.193.98.130 4000
