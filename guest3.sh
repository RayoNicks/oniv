#! /bin/bash
set -x

# 添加网卡
sudo ./onivctl add-adp onivgst3 172.16.3.31 255.255.255.0 3000 1200

# 添加网关
sudo ./onivctl add-route 172.16.1.0 255.255.255.0 172.16.3.1 onivgst3
