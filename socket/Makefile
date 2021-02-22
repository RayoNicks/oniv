all: client-udp server-udp client-tcp server-tcp

client-udp: client-udp.c c-s.h
	gcc $^ -o $@

server-udp: server-udp.c c-s.h
	gcc $^ -o $@

client-tcp: client-tcp.c c-s.h
	gcc $^ -o $@

server-tcp: server-tcp.c c-s.h
	gcc $^ -o $@

clean:
	rm -f client-udp server-udp client-tcp server-tcp