HEADERS = \
		oniv.h \
		onivadapter.h \
		onivcmd.h \
		onivcrypto.h \
		onivd.h \
		onivdb.h \
		oniventry.h \
		oniverr.h \
		onivfirst.h \
		onivframe.h \
		onivglobal.h \
		onivlog.h \
		onivmessage.h \
		onivport.h \
		onivqueue.h \
		onivsecond.h \
		onivtunnel.h \
		libonivcrypto/libonivcrypto.h

SOURCES = \
		main.cpp \
		oniv.cpp \
		onivadapter.cpp \
		onivcrypto.cpp \
		onivctl.cpp \
		onivd.cpp \
		onivdb.cpp \
		oniventry.cpp \
		oniverr.cpp \
		onivfirst.cpp \
		onivframe.cpp \
		onivglobal.cpp \
		onivlog.cpp \
		onivmessage.cpp \
		onivport.cpp \
		onivqueue.cpp \
		onivsecond.cpp \
		onivtunnel.cpp \
		libonivcrypto/libonivcrypto.c

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
		onivlog.o \
		onivmessage.o \
		onivport.o \
		onivqueue.o \
		onivsecond.o \
		onivtunnel.o \
		libonivcrypto/libonivcrypto.o

FLAGS = -Wall -g

all: onivd onivctl

onivd: $(ONIVD_OBJECTS)
	g++ $^ -o $@ -lpthread -lcrypto

onivctl: onivctl.cpp onivglobal.o onivcmd.h onivglobal.h
	g++ $^ -o $@ $(FLAGS) -std=c++11

main.o: main.cpp
	g++ $< -c -o $@ $(FLAGS) -std=c++11

%.o: %.cpp
	g++ $< -c -o $@ $(FLAGS) -std=c++11

libonivcrypto/libonivcrypto.o: libonivcrypto/libonivcrypto.c
	gcc $< -c -o $@ $(FLAGS) -lcrypto

clean:
	rm -f libonivcrypto/libonivcrypto.o
	rm -f *.o
	rm -f onivd onivctl
