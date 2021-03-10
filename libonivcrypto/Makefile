LIB = onivcrypto

FLAGS = -Wall

all : lib$(LIB).so main

main: main.cpp lib$(LIB).so libonivcrypto.h
	g++ $(FLAGS) $< -o $@ -std=c++11 -L. -l$(LIB) -lcrypto

lib$(LIB).so: libonivcrypto.c
	gcc $(FLAGS) -fPIC -shared -o $@ $<

clean:
	rm -f main lib$(LIB).so
