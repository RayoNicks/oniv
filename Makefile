HEADERS = \
		oniv.h \
		onivadapter.h \
		onivcmd.h \
		onivcrypto.h \
		onivctl.h \
		onivd.h \
		onivdb.h \
		oniventry.h \
		oniverr.h \
		onivfirst.h \
		onivframe.h \
		onivglobal.h \
		onivpacket.h \
		onivport.h \
		onivqueue.h \
		onivsecond.h \
		onivtunnel.h

SOURCES = \
		main.cpp \
		oniv.cpp \
		onivadapter.cpp \
		onivcrypto.cpp \
		onivctl.cpp \
		onivd.cpp \
		onivdb.cpp \
		oniventry.h \
		oniverr.cpp \
		onivfirst.cpp \
		onivframe.cpp \
		onivglobal.cpp \
		onivpacket.cpp \
		onivport.cpp \
		onivqueue.cpp \
		onivsecond.cpp \
		onivtunnel.cpp

ONIVD_OBJECTS = \
		main.o \
		oniv.o \
		onivadapter.o \
		onivcrypto.o \
		onivd.o \
		onivdb.o \
		oniventry.o \
		oniverr.o \
		onivfirst.o \
		onivframe.o \
		onivglobal.o \
		onivpacket.o \
		onivport.o \
		onivqueue.o \
		onivsecond.o \
		onivtunnel.o

FLAGS = -g -std=c++11 -Wall

all: onivd onivctl

onivd: $(ONIVD_OBJECTS)
	g++ $^ -o $@ -lpthread

onivctl: onivctl.cpp onivglobal.o onivcmd.h onivglobal.h
	g++ $^ -o $@ $(FLAGS)

main.o: main.cpp
	g++ $< -c -o $@ $(FLAGS)

%.o: %.cpp
	g++ $< -c -o $@ $(FLAGS)

clean:
	rm -rf *.o
	rm -rf onivd onivctl
