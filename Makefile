#
# File		: Makefile
# Description	: Build file for ARPSEC
# Created	: Thu Mar 14 07:07:42 EDT 2013
# By		: Patrick Mcdaniel
#
# Modified	: Sep 28, 2013 - add timer queue thread
# By		: daveti
# Modified	: Sep 27, 2013 - add AsWhiteList
# By		: daveti
# Modified	: Sep 18, 2013 - add AsTpmDb, tpmd and AT
# By		: daveti 
# Modified	: Aug 7, 2013 - add Kernel Relay and Netlink socket
# By		: daveti

#
# Environment Setup
   
# System setup
#GPROLOG_INCLUDE=/home/mcdaniel/gprolog-1.4.2/include
GPROLOG_INCLUDE=/usr/local/gprolog-1.4.2/include
INCLUDES=-I$(GPROLOG_INCLUDE)
LIBDIRS=

# Other parts
DEPFILE=Makefile.dep
CC=gcc
CFLAGS=-c $(INCLUDES) -g -Wall 
LINK=gcc
LINKFLAGS=-g
LIBS=-lgcrypt -ltspi -lpthread

#
# Setup builds

ASOBJS=	arpsecd.o \
	AsLog.o \
	AsLogic.o \
	AsTMeasure.o \
	AsKrnRelay.o \
	AsNetlink.o \
	AsTpmDB.o \
	AsWhiteList.o \
	AT.o \
	tpmw.o \
	timer_queue.o \
	timer_thread.o \
	AsControl.o
TPMDOBJS= tpmd.o \
	tpmw.o \
	AT.o
ARPSECPL=	arpsec.o
TARGETS	=	arpsecd \
		tpmd \
		checkproc

#
# Project Builds

ARPSEC : $(DEPFILE) $(TARGETS) 

arpsecd : $(ASOBJS) $(ARPSECPL)
	$(LINK) $(LINKFLAGS) $(ASOBJS) $(LIBS) -o $@

tpmd : $(TPMDOBJS)
	$(LINK) $(LINKFLAGS) $(TPMDOBJS) $(LIBS) -o $@

checkproc: checkproc.o
	$(CC) $< -o $@

# Various maintenance stuff
clean : 
	rm -f $(TARGETS) $(ASOBJS) $(TPMDOBJS) $(ARPSECPL) $(DEPFILE) 2>&1

install:
	install -C $(ASOBJS) $(ARPSECPL) $(TPMDOBJS) $(TARGETDIR)


# Do dependency generation
depend : $(DEPFILE)

$(DEPFILE) : $(ASOBJS:.o=.c)
	gcc -MM $(CFLAGS) $(ASOBJS:.o=.c) > $(DEPFILE)

# Inclusion
arpsec.o : arpsec.pl
include $(DEPFILE)

