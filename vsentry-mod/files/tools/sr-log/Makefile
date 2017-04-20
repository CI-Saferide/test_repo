all: libsr_log.a

#libdebug_log.a is the dependency for the executable
sr-log: libsr_log.a 
	gcc -lm -o sr-log -L. -lsr_log

sr_log.o: sr_log.c \
			 ./include/sr_log.h

	gcc -O -c -static sr_log.c

#let's link library files into a static library
libsr_log.a: sr_log.o 
	ar rcs libsr_log.a sr_log.o

libs: libsr_log.a

clean:
	rm -f sr-log *.o *.a *.gch
	rm -f main

