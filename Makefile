CC = gcc
PROJECT_CFLAGS += -Wall -Wextra $(EXTRA_CFLAGS) -I.
JSMN_CFLAGS := -DJSMN_STATIC=1 -DJSMN_STRICT=1 -Icontrib/jsmn
LIBS += -pthread -lpcap -lm

GOCC =
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
LIBS += -lgcrypt -lgpg-error
else
NDPI_WITH_GCRYPT = no
endif
ifeq ($(NDPI_WITH_PCRE),yes)
LIBS += -lpcre
else
NDPI_WITH_PCRE = no
endif

ifneq ($(CUSTOM_LIBNDPI),)
STATIC_NDPI_LIB += '$(CUSTOM_LIBNDPI)'
PROJECT_CFLAGS += '-I$(shell dirname $(CUSTOM_LIBNDPI))/../include/ndpi'
ifeq ($(findstring $*.so, $(CUSTOM_LIBNDPI)),.so)
PROJECT_CFLAGS += -Wl,-rpath='$(shell dirname $(CUSTOM_LIBNDPI))'
endif
else
STATIC_NDPI_LIB =
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

GO_DASHBOARD_SRCS := examples/go-dashboard/main.go examples/go-dashboard/ui/ui.go

RM = rm -f

all: help nDPId nDPIsrvd

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
endif

clean:
	$(RM) -f nDPId nDPIsrvd examples/c-json-stdout/c-json-stdout examples/go-dashboard/go-dashboard

help:
	@echo '------------------------------------'
	@echo 'PKG_CONFIG_BIN    = $(PKG_CONFIG_BIN)'
	@echo 'PKG_CONFIG_PREFIX = $(PKG_CONFIG_PREFIX)'
	@echo 'PC_CFLAGS         = $(PC_CFLAGS)'
	@echo 'PC_LDFLAGS        = $(PC_LDFLAGS)'
	@echo 'CC                = $(CC)'
	@echo 'CFLAGS            = $(CFLAGS)'
	@echo 'LDFLAGS           = $(LDFLAGS)'
	@echo 'PROJECT_CFLAGS    = $(PROJECT_CFLAGS)'
	@echo 'LIBS              = $(LIBS)'
	@echo 'GOCC              = $(GOCC)'
	@echo 'GOFLAGS           = $(GOFLAGS)'
	@echo 'CUSTOM_LIBNDPI    = $(CUSTOM_LIBNDPI)'
	@echo 'NDPI_WITH_GCRYPT  = $(NDPI_WITH_GCRYPT)'
	@echo 'NDPI_WITH_PCRE    = $(NDPI_WITH_PCRE)'
	@echo 'ENABLE_DEBUG      = $(ENABLE_DEBUG)'
	@echo 'ENABLE_SANITIZER  = $(ENABLE_SANITIZER)'
	@echo 'ENABLE_SANITIZER_THREAD = $(ENABLE_SANITIZER_THREAD)'
	@echo '------------------------------------'

.PHONY: all clean help
