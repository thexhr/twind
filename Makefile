CC = cc

#CFLAGS  = -g3 -ggdb
CFLAGS  = -O2

CFLAGS += -pipe -fPIE -fdiagnostics-color -Wno-unknown-warning-option -Wpedantic
CFLAGS += -Wall -Werror-implicit-function-declaration -Wno-format-truncation
CFLAGS += -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations
CFLAGS += -Wshadow -Wpointer-arith -Wcast-qual -Wsign-compare
CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Werror=format-security
LDADD = -Wl,-z,now -Wl,-z,relro -pie -lssl -lcrypto -lpthread

BIN  = twind
OBJS = twind.o gemini.o log.o request.o mime.o util.o

INSTALL ?= install -p

PREFIX ?= /usr/local
SBIN ?= $(PREFIX)/sbin
MAN ?= $(PREFIX)/man
GEMINIDIR ?= /var/twind
CONFDIR ?= /etc/twind
HN ?= gemini.example.com

UID = 4000

all: $(BIN)

install: all
	$(INSTALL) -D -m 644 -o root $(BIN).8 $(DESTDIR)$(MAN)/man8/$(BIN).8
	$(INSTALL) -D -m 755 -o root $(BIN) $(DESTDIR)$(SBIN)/$(BIN)
	$(INSTALL) -d -m 750 -o root $(DESTDIR)$(CONFDIR)
	$(INSTALL) -d -m 755 -o root $(DESTDIR)$(GEMINIDIR)
	$(INSTALL) -d -m 755 -o _twind -g _twind $(DESTDIR)$(GEMINIDIR)/logs

user:
	@useradd -d $(DESTDIR)$(GEMINIDIR) -s /sbin/nologin -u $(UID) _twind

setuptls:
	@openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes -keyout $(DESTDIR)$(CONFDIR)/twind.key.pem -new -subj /CN=$(HN) -out $(DESTDIR)$(CONFDIR)/twind.cert.pem -addext subjectAltName=DNS:$(HN)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDADD)

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(BIN) $(OBJS)
