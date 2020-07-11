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
CFLAGS += -O0 -g3 -fno-omit-frame-pointer
else
ENABLE_DEBUG = no
endif

ifeq ($(ENABLE_SANITIZER),yes)
CFLAGS += -fsanitize=address -fsanitize=undefined -fsanitize=enum -fsanitize=leak
LIBS += -lasan -lubsan
else
ENABLE_SANITIZER = no
endif

ifeq ($(ENABLE_SANITIZER_THREAD),yes)
CFLAGS += -fsanitize=undefined -fsanitize=enum -fsanitize=thread
LIBS += -lubsan
else
ENABLE_SANITIZER_THREAD = no
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

nDPId: help nDPId.c
	$(CC) $(CFLAGS) nDPId.c -o $@ $(LDFLAGS) $(LIBS)

clean:
	$(RM) nDPId

help:
	@echo 'CC               = $(CC)'
	@echo 'CFLAGS           = $(CFLAGS)'
	@echo 'LIBS             = $(LIBS)'
	@echo 'CUSTOM_LIBNDPI   = $(CUSTOM_LIBNDPI)'
	@echo 'ENABLE_DEBUG     = $(ENABLE_DEBUG)'
	@echo 'ENABLE_SANITIZER = $(ENABLE_SANITIZER)'
	@echo 'ENABLE_SANITIZER_THREAD = $(ENABLE_SANITIZER_THREAD)'
	@echo 'DISABLE_JSONIZER = $(DISABLE_JSONIZER)'
	@echo 'EXTRA_VERBOSE    = $(EXTRA_VERBOSE)'

.PHONY: help
