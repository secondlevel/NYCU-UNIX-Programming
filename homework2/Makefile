all: logger.so logger

logger.so: hw2.c
	gcc -o logger.so -shared -fPIC hw2.c -ldl

logger: logger.cpp
	g++ -o logger logger.cpp

.PHONY: clean all

clean:
	rm -f logger.so logger