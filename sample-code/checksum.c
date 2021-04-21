#include <stdio.h>
#include <string.h>

unsigned short checksum(const char *buf, size_t len)
{
    if(len % 2 != 0){
        return 0;
    }
    unsigned int cs = 0;
    unsigned short *p = (unsigned short*)buf;
    while(len > 0){
        cs += *p++;
        len -= 2;
    }
    cs = (cs >> 16) + (cs & 0xFFFF);
    cs += cs >> 16;
    return ~cs;
}

int main()
{
    char hdr[] = { "\x45\x00\x00\x31\x89\xF5\x00\x00\x6e\x06\x00\x00\xDE\xB7\x45\x5D\xC0\xA8\x00\xDC" };
    char hdr1[] = { "\x45\x00\x00\x54\x5d\xc6\x40\x00\x40\x01\x00\x00\xac\x10\x01\x0b\xac\x10\x01\x01" };
    char hdr2[] = { "\x45\x00\x00\x54\x5d\xe8\x40\x00\x40\x01\x00\x00\xac\x10\x01\x0b\xac\x10\x01\x01" };
    char hdr3[] = { "\x45\x00\x00\x54\x4b\x8d\x40\x00\x40\x01\x00\x00\xac\x10\x01\x0b\xac\x10\x01\x01" };
    unsigned short cs = checksum(hdr3, sizeof(hdr3) - 1);
    printf("hdr3 checksum = %x\n", cs);
    return 0;
}
