CFLAGS		= -g -O2 -w
LINKFLAGS	= -Wall -Wl,--no-as-needed
LIBS		= -lpthread -lcrypto -ldl
DESTDIR		=
PREFIX		= /usr/local
SBINDIR		= $(PREFIX)/sbin
DEPS 		= krackips.h

DETECTDIR	= ./detect
MODDIR		= ./module
NETDIR		= ./netstack

$(DETECTDIR)/%.o: %.c $(DEPS)
	gcc -c -o $@ $< $(CFLAGS)
	
$(MODDIR)/%.o: %.c $(DEPS)
	gcc -c -o $@ $< $(CFLAGS)
	
$(NETDIR)/%.o: %.c $(DEPS)
	gcc -c -o $@ $< $(CFLAGS)
	
_DET = detect.o 
DET = $(patsubst %,$(DETECTDIR)/%,$(_DET))

_MOD = crypto-fnv1a.o hexval.o mystring.o pcapfile.o pcaplive.o pixie.o sprintf_s.o 
MOD = $(patsubst %,$(MODDIR)/%,$(_MOD))
	
_NET = stackwifi.o 
NET = $(patsubst %,$(NETDIR)/%,$(_NET))

	
all: krackip

krackip: $(DET) $(MOD) $(NET) main.c
	gcc $(CFLAGS) $^ -o $@ $(LIBS) $(LINKFLAGS)

install: 

clean:
	rm -f krackip
	rm -rf detect/*.o
	rm -rf module/*.o	

distclean: clean
