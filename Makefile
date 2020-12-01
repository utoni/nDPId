CC = gcc
PROJECT_CFLAGS += -Wall -Wextra $(EXTRA_CFLAGS) -I.
JSMN_CFLAGS := -DJSMN_STATIC=1 -DJSMN_STRICT=1 -Idependencies
LIBS += -pthread -lpcap -lm

GOCC =
GOFLAGS = -ldflags='-s -w'

ifneq ($(PKG_CONFIG_BIN),)
PC_CFLAGS=$(shell $(PKG_CONFIG_BIN) --cflags libndpi)
PC_LDFLAGS=$(shell $(PKG_CONFIG_BIN) --libs libndpi)

ifneq ($(PKG_CONFIG_PATH),)
PROJECT_CFLAGS += -Wl,-rpath='$(shell dirname $(PKG_CONFIG_PATH))'
endif

else # PKG_CONFIG_BIN

ifeq ($(NDPI_WITH_GCRYPT),yes)
LIBS += -lgcrypt -lgpg-error
endif
ifeq ($(NDPI_WITH_PCRE),yes)
LIBS += -lpcre
endif

ifneq ($(CUSTOM_LIBNDPI),)
STATIC_NDPI_LIB += '$(CUSTOM_LIBNDPI)'
PROJECT_CFLAGS += '-I$(shell dirname $(CUSTOM_LIBNDPI))/../include/ndpi'
ifeq ($(findstring $*.so, $(CUSTOM_LIBNDPI)),.so)
PROJECT_CFLAGS += -Wl,-rpath='$(shell dirname $(CUSTOM_LIBNDPI))'
endif
else
LIBS += -lndpi
endif

endif # PKG_CONFIG_BIN

ifeq ($(ENABLE_DEBUG),yes)
PROJECT_CFLAGS += -O0 -g3 -fno-omit-frame-pointer -fno-inline
endif

ifeq ($(ENABLE_SANITIZER),yes)
PROJECT_CFLAGS += -fsanitize=address -fsanitize=undefined -fsanitize=enum -fsanitize=leak
LIBS += -lasan -lubsan
endif

ifeq ($(ENABLE_SANITIZER_THREAD),yes)
PROJECT_CFLAGS += -fsanitize=undefined -fsanitize=enum -fsanitize=thread
LIBS += -lubsan
endif

GO_DASHBOARD_SRCS := examples/go-dashboard/main.go examples/go-dashboard/ui/ui.go

RM = rm -f
INSTALL = install

ifeq ($(ENABLE_DEBUG),yes)
INSTALL_ARGS = -s
endif

all: help nDPId nDPIsrvd examples

examples: examples/c-captured/c-captured examples/c-json-stdout/c-json-stdout examples/go-dashboard/go-dashboard

nDPId: nDPId.c utils.c
	$(CC) $(PROJECT_CFLAGS) $(CFLAGS) $(PC_CFLAGS) $^ -o $@ $(LDFLAGS) $(PC_LDFLAGS) $(STATIC_NDPI_LIB) $(LIBS)

nDPIsrvd: nDPIsrvd.c utils.c
	$(CC) $(PROJECT_CFLAGS) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(STATIC_NDPI_LIB) $(LIBS)

examples/c-captured/c-captured: examples/c-captured/c-captured.c
	$(CC) $(PROJECT_CFLAGS) $(CFLAGS) $(JSMN_CFLAGS) $@.c -o $@ $(LDFLAGS) $(LIBS)

examples/c-json-stdout/c-json-stdout: examples/c-json-stdout/c-json-stdout.c
	$(CC) $(PROJECT_CFLAGS) $(CFLAGS) $(JSMN_CFLAGS) $@.c -o $@ $(LDFLAGS) $(LIBS)

examples/go-dashboard/go-dashboard: $(GO_DASHBOARD_SRCS)
ifneq ($(GOCC),)
	cd examples/go-dashboard && GO111MODULE=on $(GOCC) mod vendor
	cd examples/go-dashboard && GO111MODULE=on $(GOCC) build $(GOFLAGS) .
else
	@echo '*** Not building examples/go-dashboard/go-dashboard as it requires GOCC to be set ***'
endif

install: all
	$(INSTALL) -d '$(DESTDIR)$(PREFIX)/bin' '$(DESTDIR)$(PREFIX)/sbin'
	$(INSTALL) $(INSTALL_ARGS) -t '$(DESTDIR)$(PREFIX)/bin' nDPIsrvd
	$(INSTALL) $(INSTALL_ARGS) -t '$(DESTDIR)$(PREFIX)/sbin' nDPId

clean:
	$(RM) -f nDPId nDPIsrvd examples/c-captured/c-captured examples/c-json-stdout/c-json-stdout examples/go-dashboard/go-dashboard

help:
	@echo '------------------------------------'
	@echo 'PKG_CONFIG_BIN    = $(PKG_CONFIG_BIN)'
	@echo 'PKG_CONFIG_PATH   = $(PKG_CONFIG_PATH)'
	@echo 'PC_CFLAGS         = $(PC_CFLAGS)'
	@echo 'PC_LDFLAGS        = $(PC_LDFLAGS)'
	@echo 'CC                = $(CC)'
	@echo 'CFLAGS            = $(CFLAGS)'
	@echo 'LDFLAGS           = $(LDFLAGS)'
	@echo 'PROJECT_CFLAGS    = $(PROJECT_CFLAGS)'
	@echo 'LIBS              = $(LIBS)'
	@echo 'GOCC              = $(GOCC)'
	@echo 'GOFLAGS           = $(GOFLAGS)'
ifeq ($(PKG_CONFIG_BIN),)
	@echo 'CUSTOM_LIBNDPI    = $(CUSTOM_LIBNDPI)'
ifeq ($(NDPI_WITH_GCRYPT),yes)
	@echo 'NDPI_WITH_GCRYPT  = yes'
else
	@echo 'NDPI_WITH_GCRYPT  = no'
endif
ifeq ($(NDPI_WITH_PCRE),yes)
	@echo 'NDPI_WITH_PCRE    = yes'
else
	@echo 'NDPI_WITH_PCRE    = no'
endif
endif # PKG_CONFIG_BIN
ifeq ($(ENABLE_DEBUG),yes)
	@echo 'ENABLE_DEBUG      = yes'
else
	@echo 'ENABLE_DEBUG      = no'
endif
ifeq ($(ENABLE_SANITIZER),yes)
	@echo 'ENABLE_SANITIZER  = yes'
else
	@echo 'ENABLE_SANITIZER  = no'
endif
ifeq ($(ENABLE_SANITIZER_THREAD),yes)
	@echo 'ENABLE_SANITIZER_THREAD = yes'
else
	@echo 'ENABLE_SANITIZER_THREAD = no'
endif
	@echo '------------------------------------'

mocksrvd:
	nc -k -l -U /tmp/ndpid-collector.sock

run-nDPIsrvd: nDPIsrvd
	./nDPIsrvd -l

run-nDPId: nDPId
	sudo ./nDPId -l -a run-test -u $(shell id -u -n)

.PHONY: all examples install clean help mocksrvd run
