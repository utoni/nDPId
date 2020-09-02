CC = gcc
PROJECT_CFLAGS += -Wall -Wextra $(EXTRA_CFLAGS) -I.
LIBS += -pthread -lpcap -lm

GOCC = go
GOFLAGS = -ldflags='-s -w'

ifneq ($(PKG_CONFIG_BIN),)
ifneq ($(PKG_CONFIG_PREFIX),)
PC_CFLAGS=$(shell PKG_CONFIG_PATH=$(shell realpath $(PKG_CONFIG_PREFIX))/lib/pkgconfig $(PKG_CONFIG_BIN) --define-variable=prefix=$(shell realpath $(PKG_CONFIG_PREFIX)) --cflags libndpi)
PC_LDFLAGS=$(shell PKG_CONFIG_PATH=$(shell realpath $(PKG_CONFIG_PREFIX))/lib/pkgconfig $(PKG_CONFIG_BIN) --define-variable=prefix=$(shell realpath $(PKG_CONFIG_PREFIX)) --libs libndpi)
PROJECT_CFLAGS += -Wl,-rpath='$(shell realpath $(PKG_CONFIG_PREFIX)/lib)'
else
PC_CFLAGS=$(shell $(PKG_CONFIG_BIN) --cflags libndpi)
PC_LDFLAGS=$(shell $(PKG_CONFIG_BIN) --libs libndpi)
endif

else

ifeq ($(NDPI_WITH_GCRYPT),yes)
LIBS += -lgcrypt
else
NDPI_WITH_GCRYPT = no
endif
ifeq ($(NDPI_WITH_PCRE),yes)
LIBS += -lpcre
else
NDPI_WITH_PCRE = no
endif

ifneq ($(CUSTOM_LIBNDPI),)
LIBS += '$(CUSTOM_LIBNDPI)'
PROJECT_CFLAGS += '-I$(shell dirname $(CUSTOM_LIBNDPI))/../include/ndpi'
ifeq ($(findstring $*.so, $(CUSTOM_LIBNDPI)),.so)
PROJECT_CFLAGS += -Wl,-rpath='$(shell dirname $(CUSTOM_LIBNDPI))'
endif
else
CUSTOM_LIBNDPI = no
LIBS += -lndpi
endif

endif

ifeq ($(ENABLE_DEBUG),yes)
PROJECT_CFLAGS += -O0 -g3 -fno-omit-frame-pointer -fno-inline
else
ENABLE_DEBUG = no
endif

ifeq ($(ENABLE_SANITIZER),yes)
PROJECT_CFLAGS += -fsanitize=address -fsanitize=undefined -fsanitize=enum -fsanitize=leak
LIBS += -lasan -lubsan
else
ENABLE_SANITIZER = no
endif

ifeq ($(ENABLE_SANITIZER_THREAD),yes)
PROJECT_CFLAGS += -fsanitize=undefined -fsanitize=enum -fsanitize=thread
LIBS += -lubsan
else
ENABLE_SANITIZER_THREAD = no
endif

ifneq ($(DISABLE_JSMN),yes)
DISABLE_JSMN = no
endif

GO_DASHBOARD_SRCS := examples/go-dashboard/main.go examples/go-dashboard/ui/ui.go

RM = rm -f

all: help nDPId nDPIsrvd

examples: examples/c-json-stdout/c-json-stdout examples/go-dashboard/go-dashboard

nDPId: nDPId.c utils.c
	$(CC) $(PROJECT_CFLAGS) $(CFLAGS) $(PC_CFLAGS) $^ -o $@ $(LDFLAGS) $(PC_LDFLAGS) $(LIBS)

nDPIsrvd: nDPIsrvd.c utils.c
	$(CC) $(PROJECT_CFLAGS) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

examples/c-json-stdout/c-json-stdout: examples/c-json-stdout/c-json-stdout.c
ifneq ($(DISABLE_JSMN),yes)
	$(CC) $(PROJECT_CFLAGS) $(CFLAGS) -DJSMN_STATIC=1 -DJSMN_STRICT=1 -DUSE_JSON=1 $@.c -o $@ $(LDFLAGS) $(LIBS)
else
	$(CC) $(PROJECT_CFLAGS) $(CFLAGS) $@.c -o $@ $(LDFLAGS) $(LIBS)
endif

examples/go-dashboard/go-dashboard: $(GO_DASHBOARD_SRCS)
ifneq ($(GOCC),)
	cd examples/go-dashboard && GO111MODULE=on $(GOCC) mod vendor
	cd examples/go-dashboard && GO111MODULE=on $(GOCC) build $(GOFLAGS) .
endif

clean:
	$(RM) -f nDPId nDPIsrvd examples/c-json-stdout/c-json-stdout examples/go-dashboard/go-dashboard

help:
	@echo '------------------------------------'
	@echo 'PKG_CONFIG_BIN   = $(PKG_CONFIG_BIN)'
	@echo 'PKG_CONFIG_PREFIX = $(PKG_CONFIG_PREFIX)'
	@echo 'PC_CFLAGS        = $(PC_CFLAGS)'
	@echo 'PC_LDFLAGS       = $(PC_LDFLAGS)'
	@echo 'CC               = $(CC)'
	@echo 'CFLAGS           = $(CFLAGS)'
	@echo 'LDFLAGS          = $(LDFLAGS)'
	@echo 'PROJECT_CFLAGS	= $(PROJECT_CFLAGS)'
	@echo 'LIBS             = $(LIBS)'
	@echo 'GOCC             = $(GOCC)'
	@echo 'GOFLAGS          = $(GOFLAGS)'
	@echo 'CUSTOM_LIBNDPI   = $(CUSTOM_LIBNDPI)'
	@echo 'NDPI_WITH_GCRYPT = $(NDPI_WITH_GCRYPT)'
	@echo 'NDPI_WITH_PCRE   = $(NDPI_WITH_PCRE)'
	@echo 'ENABLE_DEBUG     = $(ENABLE_DEBUG)'
	@echo 'ENABLE_SANITIZER = $(ENABLE_SANITIZER)'
	@echo 'ENABLE_SANITIZER_THREAD = $(ENABLE_SANITIZER_THREAD)'
	@echo 'DISABLE_JSMN     = $(DISABLE_JSMN)'
	@echo '------------------------------------'

.PHONY: all clean help
