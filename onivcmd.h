#ifndef _ONIV_CMD_H_
#define _ONIV_CMD_H_

// defining interaction command between switcher and controller
// commands
#define COMMAND_STOP        0x00
#define COMMAND_ADD_ADP     0x10
#define COMMAND_DEL_ADP     0x11
#define COMMAND_CLR_ADP     0x12
#define COMMAND_ADD_TUN     0x20
#define COMMAND_DEL_TUN     0x21
#define COMMAND_CLR_TUN     0x22
#define COMMAND_ADD_ROU     0x30
#define COMMAND_DEL_ROU     0x31

// command type for add or delete device or tunnel
/*
0               1               2               3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    command    |      len      |   parameter   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#endif
