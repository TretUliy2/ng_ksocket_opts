default:
	cc -c main.c
	cc -lc -lnetgraph -o main *.o
clean:
	rm -rf *.o *.core main
#CC=clang
#WARNS?= 3
#PROG= main

#SRCS= main.c 
#SRCS+= config.h ng-r.h 
#LDADD+= -lc -lnetgraph


#DESTDIR= /usr/local
#BINDIR= /bin

#MAN=

#afterinstall: 
#	install -o root -g wheel -m 555   rc/mcastng /usr/local/etc/rc.d

#.include <bsd.prog.mk>
