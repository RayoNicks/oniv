FLAGS = -Wall

all : main

main: main.cpp libonivcrypto.o libonivcrypto.h
	g++ $(FLAGS) $^ -o $@ -std=c++11 -lcrypto

libonivcrypto.o: libonivcrypto.c
	gcc $(FLAGS) -c -o $@ $< -lcrypto

clean:
	rm -f main libonivcrypto.o
