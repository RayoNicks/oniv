#! /bin/bash
set -x

# 添加网卡
sudo ./onivctl add-adp onivgst4 172.16.4.41 255.255.255.0 4000 1300

# 添加网关
sudo ./onivctl add-route 172.16.1.0 255.255.255.0 172.16.4.1 onivgst4
sudo ./onivctl add-route 172.16.3.0 255.255.255.0 172.16.4.1 onivgst4
