CC = gcc
CFLAGS += -Wall -Wextra $(EXTRA_CFLAGS)
LIBS += -pthread -lpcap -lm

ifneq ($(CUSTOM_LIBNDPI),)
LIBS += '$(CUSTOM_LIBNDPI)'
CFLAGS += '-I$(shell dirname $(CUSTOM_LIBNDPI))/../include'
ifeq ($(findstring $*.so, $(CUSTOM_LIBNDPI)),.so)
CFLAGS += -Wl,-rpath='$(shell dirname $(CUSTOM_LIBNDPI))'
endif
else
CUSTOM_LIBNDPI = no
LIBS += -lndpi
endif

ifeq ($(ENABLE_DEBUG),yes)
CFLAGS += -Og -g3
else
ENABLE_DEBUG = no
endif

ifeq ($(ENABLE_SANITIZER),yes)
CFLAGS += -fsanitize=address -fsanitize=undefined -fsanitize=leak
LIBS += -lasan -lubsan
else
ENABLE_SANITIZER = no
endif

ifeq ($(DISABLE_JSONIZER),yes)
CFLAGS += -DDISABLE_JSONIZER
else
DISABLE_JSONIZER = no
endif

ifeq ($(EXTRA_VERBOSE),yes)
CFLAGS += -DEXTRA_VERBOSE
else
EXTRA_VERBOSE = no
endif

RM = rm -f

main: help main.c
	$(CC) $(CFLAGS) main.c -o $@ $(LDFLAGS) $(LIBS)

clean:
	$(RM) main

help:
	@echo 'CC               = $(CC)'
	@echo 'CFLAGS           = $(CFLAGS)'
	@echo 'LIBS             = $(LIBS)'
	@echo 'CUSTOM_LIBNDPI   = $(CUSTOM_LIBNDPI)'
	@echo 'ENABLE_DEBUG     = $(ENABLE_DEBUG)'
	@echo 'ENABLE_SANITIZER = $(ENABLE_SANITIZER)'
	@echo 'DISABLE_JSONIZER = $(DISABLE_JSONIZER)'
	@echo 'EXTRA_VERBOSE    = $(EXTRA_VERBOSE)'

.PHONY: help
