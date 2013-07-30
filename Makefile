#
# File		: Makefile
# Description	: Build file for ARPSEC
# Created	: Thu Mar 14 07:07:42 EDT 2013
# By		: Patrick Mcdaniel
#
# Modified	: Jul 7, 2013
# By		: daveti

#
# Environment Setup
   
# System setup
#GPROLOG_INCLUDE=/home/mcdaniel/gprolog-1.4.2/include
GPROLOG_INCLUDE=/usr/local/gprolog-1.4.4/include
INCLUDES=-I$(GPROLOG_INCLUDE)
LIBDIRS=

# Other parts
DEPFILE=Makefile.dep
CC=gcc
CFLAGS=-c $(INCLUDES) -g -Wall 
LINK=gcc
LINKFLAGS=-g
LIBS=-lgcrypt

#
# Setup builds

ASOBJS=	arpsecd.o \
	AsLog.o \
	AsLogic.o \
	AsTMeasure.o \
	AsKrnRelay.o \
	AsControl.o
ARPSECPL=	arpsec.o
TARGETS	=	arpsecd \
		checkproc

#
# Project Builds

ARPSEC : $(DEPFILE) $(TARGETS) 

arpsecd : $(ASOBJS) $(ARPSECPL)
	$(LINK) $(LINKFLAGS) $(ASOBJS) $(LIBS) -o $@

checkproc: checkproc.o
	$(CC) $< -o $@

# Various maintenance stuff
clean : 
	rm -f $(TARGETS) $(ASOBJS) $(ARPSECPL) $(DEPFILE) 

install:
	install -C $(ASOBJS) $(ARPSECPL) $(TARGETDIR)


# Do dependency generation
depend : $(DEPFILE)

$(DEPFILE) : $(ASOBJS:.o=.c)
	gcc -MM $(CFLAGS) $(ASOBJS:.o=.c) > $(DEPFILE)

# Inclusion
arpsec.o : arpsec.pl
include $(DEPFILE)

