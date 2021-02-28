CC = gcc
PROJECT_CFLAGS += -Wall -Wextra $(EXTRA_CFLAGS) -I.
DEPS_CFLAGS := -DJSMN_STATIC=1 -DJSMN_STRICT=1 -Idependencies -Idependencies/uthash/src
LIBS += -pthread -lpcap -lm -lmaxminddb

GOCC =
GOFLAGS = -ldflags='-s -w'

UNIX_SOCK_DISTRIBUTOR = /tmp/ndpid-distributor.sock
UNIX_SOCK_COLLECTOR = /tmp/ndpid-collector.sock

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

ifeq ($(ENABLE_MEMORY_PROFILING),yes)
PROJECT_CFLAGS += -DENABLE_MEMORY_PROFILING=1
DEPS_CFLAGS += -Duthash_malloc=nDPIsrvd_uthash_malloc -Duthash_free=nDPIsrvd_uthash_free
endif

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
	$(CC) $(PROJECT_CFLAGS) $(CFLAGS) $(DEPS_CFLAGS) $^ -o $@ $(LDFLAGS) $(STATIC_NDPI_LIB) $(LIBS)

examples/c-captured/c-captured: examples/c-captured/c-captured.c utils.c
	$(CC) $(PROJECT_CFLAGS) $(CFLAGS) $(DEPS_CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

examples/c-json-stdout/c-json-stdout: examples/c-json-stdout/c-json-stdout.c
	$(CC) $(PROJECT_CFLAGS) $(CFLAGS) $(DEPS_CFLAGS) $@.c -o $@ $(LDFLAGS) $(LIBS)

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
	$(INSTALL) $(INSTALL_ARGS) -t '$(DESTDIR)$(PREFIX)/bin' examples/c-captured/c-captured
	$(INSTALL) $(INSTALL_ARGS) -t '$(DESTDIR)$(PREFIX)/bin' examples/c-json-stdout/c-json-stdout
ifneq ($(GOCC),)
	$(INSTALL) $(INSTALL_ARGS) -t '$(DESTDIR)$(PREFIX)/bin' examples/go-dashboard/go-dashboard
endif

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
	@echo 'EXTRA_CFLAGS      = $(EXTRA_CFLAGS)'
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
ifeq ($(ENABLE_MEMORY_PROFILING),yes)
	@echo 'ENABLE_MEMORY_PROFILING = yes'
else
	@echo 'ENABLE_MEMORY_PROFILING = no'
endif
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

run-mocksrvd:
	nc -k -l -U $(UNIX_SOCK_COLLECTOR)

run-raw-out:
	nc -U $(UNIX_SOCK_DISTRIBUTOR)

run-nDPIsrvd: nDPIsrvd
	./nDPIsrvd -l -c $(UNIX_SOCK_COLLECTOR) -s $(UNIX_SOCK_DISTRIBUTOR)

run-nDPId: nDPId
	sudo ./nDPId -l -c $(UNIX_SOCK_COLLECTOR) -a run-test -u $(shell id -u -n)

.PHONY: all examples install clean help run-mocksrvd run-raw-out run-nDPIsrvd run-nDPId
