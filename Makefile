# Makefile
# Author: Milan Kubík, xkubik17@stud.fit.vutbr.cz
# Date: October 2010
# 
# Description
# Router Advertisement

AUTH=xkubik17

CC=gcc
#CFLAGS=-std=c99 -Wall -pedantic -D_GNU_SOURCE
CFLAGS=-std=c99 -Wall -pedantic -g -D_GNU_SOURCE
LIBS=-lpcap

EXEC=rasniffer
SRC=rasniffer.c params.c params.h sniffer.c sniffer.h sender.c sender.h mac.c mac.h

OTHER=Readme manual.pdf

RM=rm -fr

.PHONY: clean clear pack

# compile rules
all: $(EXEC) 

$(EXEC): rasniffer.o params.o sniffer.o sender.o mac.o
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

$rasniffer.o: rasniffer.c
	$(CC) $(CFLAGS) $(LIBS) -c -o $@ $<

$params.o: params.c
	$(CC) $(CFLAGS) $(LIBS) -c -o $@ $<

$sniffer.o: sniffer.c
	$(CC) $(CFLAGS) $(LIBS) -c -o $@ $<

$sender.o: sender.c
	$(CC) $(CFLAGS) $(LIBS) -c -o $@ $<

$mac.o: mac.c
	$(CC) $(CFLAGS) $(LIBS) -c -o $@ $<

# printmac
printmac: printmac.c mac.o
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

# other rules
clear: clean

clean:
	$(RM) *.o $(EXEC) printmac

pack:
	tar cvf $(AUTH).tar $(SRC) $(OTHER) Makefile
