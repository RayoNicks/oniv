HEADERS = \
		onivadapter.h \
		onivcmd.h \
		onivctl.h \
		onivd.h \
		oniventry.h \
		oniverr.h \
		onivfdb.h \
		onivframe.h \
		onivglobal.h \
		onivpacket.h \
		onivport.h \
		onivqueue.h \
		onivtunnel.h

SOURCES = \
		main.cpp \
		onivadapter.cpp \
		onivctl.cpp \
		onivd.cpp \
		oniventry.h \
		oniverr.cpp \
		onivfdb.cpp \
		onivframe.cpp \
		onivglobal.cpp \
		onivpacket.cpp \
		onivport.cpp \
		onivqueue.cpp \
		onivtunnel.cpp

OBJECTS = \
		main.o \
		onivadapter.o \
		onivctl.o \
		onivd.o \
		oniventry.h \
		oniverr.o \
		onivfdb.o \
		onivframe.o \
		onivglobal.o \
		onivpacket.o \
		onivport.o \
		onivqueue.o \
		onivtunnel.o

FLAGS = -g -std=c++11

all: onivd onivctl

onivd: main.o onivadapter.o onivd.o oniventry.o oniverr.o onivfdb.o onivframe.o onivglobal.o onivpacket.o onivport.o onivqueue.o onivtunnel.o
	g++ $^ -o $@ -lpthread

onivctl: onivctl.cpp onivglobal.o onivcmd.h onivglobal.h
	g++ $^ -o $@ $(FLAGS)

main.o: main.cpp
	g++ $< -c -o $@ $(FLAGS)

%.o: %.cpp %.h
	g++ $< -c -o $@ $(FLAGS)

clean:
	rm -rf *.o
	rm -rf onivd onivctl
