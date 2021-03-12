AUTOMAKE_OPTIONS = foreign subdir-objects
AM_CXXFLAGS = -Wall -std=c++11
AM_CFLAGS = -Wall

SUBDIRS = libonivcrypto socket

noinst_PROGRAMS = onivd onivctl

onivd_SOURCES = main.cpp \
	oniv.cpp \
	onivadapter.cpp \
	onivcrypto.cpp \
	onivd.cpp \
	onivdb.cpp \
	oniventry.cpp \
	oniverr.cpp \
	onivfirst.cpp \
	onivframe.cpp \
	onivglobal.cpp \
	onivpacket.cpp \
	onivport.cpp \
	onivqueue.cpp \
	onivsecond.cpp \
	onivtunnel.cpp

onivd_SOURCES += libonivcrypto/libonivcrypto.c

onivctl_SOURCES = \
	onivctl.cpp \
	onivglobal.cpp

noinst_HEADERS = \
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
	onivpacket.h \
	onivport.h \
	onivqueue.h \
	onivsecond.h \
	onivtunnel.h

noinst_HEADERS += libonivcrypto/libonivcrypto.h

onivd_LDADD = -lcrypto -lpthread

EXTRA_DIST = README.md guest1.sh guest2.sh guest3.sh guest4.sh
