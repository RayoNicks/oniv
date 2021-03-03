#! /bin/bash
set -x

# 添加网卡
sudo ./onivctl add-adp onivgst1 172.16.1.11 255.255.255.0 1000 1200

# 添加网关
sudo ./onivctl add-route 172.16.3.0 255.255.255.0 172.16.1.1 onivgst1
sudo ./onivctl add-route 172.16.4.0 255.255.255.0 172.16.1.1 onivgst1

# 添加到网关的隧道
sudo ./onivctl add-tun 42.193.98.130 1000
