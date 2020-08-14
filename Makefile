CC = gcc
PROJECT_CFLAGS += -Wall -Wextra $(EXTRA_CFLAGS) -I.
LIBS += -pthread -lpcap -lm

ifneq ($(CUSTOM_LIBNDPI),)
LIBS += '$(CUSTOM_LIBNDPI)'
PROJECT_CFLAGS += '-I$(shell dirname $(CUSTOM_LIBNDPI))/../include'
ifeq ($(findstring $*.so, $(CUSTOM_LIBNDPI)),.so)
PROJECT_CFLAGS += -Wl,-rpath='$(shell dirname $(CUSTOM_LIBNDPI))'
endif
else
CUSTOM_LIBNDPI = no
LIBS += -lndpi
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

RM = rm -f

all: help nDPId nDPIsrvd

examples: examples/c-json-stdout/c-json-stdout

nDPId: nDPId.c utils.c
	$(CC) $(PROJECT_CFLAGS) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

nDPIsrvd: nDPIsrvd.c utils.c
	$(CC) $(PROJECT_CFLAGS) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

examples/c-json-stdout/c-json-stdout:
ifneq ($(DISABLE_JSMN),yes)
	$(CC) $(PROJECT_CFLAGS) $(CFLAGS) -DJSMN_STATIC=1 -DJSMN_STRICT=1 -DUSE_JSON=1 $@.c -o $@ $(LDFLAGS) $(LIBS)
else
	$(CC) $(PROJECT_CFLAGS) $(CFLAGS) $@.c -o $@ $(LDFLAGS) $(LIBS)
endif

clean:
	$(RM) -f nDPId nDPIsrvd examples/c-json-stdout/c-json-stdout

help:
	@echo '------------------------------------'
	@echo 'CC               = $(CC)'
	@echo 'CFLAGS           = $(CFLAGS)'
	@echo 'LDFLAGS          = $(LDFLAGS)'
	@echo 'PROJECT_CFLAGS	= $(PROJECT_CFLAGS)'
	@echo 'LIBS             = $(LIBS)'
	@echo 'CUSTOM_LIBNDPI   = $(CUSTOM_LIBNDPI)'
	@echo 'ENABLE_DEBUG     = $(ENABLE_DEBUG)'
	@echo 'ENABLE_SANITIZER = $(ENABLE_SANITIZER)'
	@echo 'ENABLE_SANITIZER_THREAD = $(ENABLE_SANITIZER_THREAD)'
	@echo 'DISABLE_JSMN     = $(DISABLE_JSMN)'
	@echo '------------------------------------'

.PHONY: all clean help
