ALL: vlarp-me-arder

vlarp-me-arder: vlarp-me-arder.c
	gcc -g -Wall -o vlarp-me-arder vlarp-me-arder.c

clean:
	-rm vlarp-me-arder

.PHONY: clean
