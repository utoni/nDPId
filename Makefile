CC = gcc
PROJECT_CFLAGS += -Wall -Wextra $(EXTRA_CFLAGS)
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
PROJECT_CFLAGS += -O0 -g3 -fno-omit-frame-pointer
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

RM = rm -f

nDPId: help nDPId.c
	$(CC) $(PROJECT_CFLAGS) $(CFLAGS) nDPId.c -o $@ $(LDFLAGS) $(LIBS)

clean:
	$(RM) nDPId

help:
	@echo 'CC               = $(CC)'
	@echo 'CFLAGS           = $(CFLAGS)'
	@echo 'PROJECT_CFLAGS	= $(PROJECT_CFLAGS)'
	@echo 'LIBS             = $(LIBS)'
	@echo 'CUSTOM_LIBNDPI   = $(CUSTOM_LIBNDPI)'
	@echo 'ENABLE_DEBUG     = $(ENABLE_DEBUG)'
	@echo 'ENABLE_SANITIZER = $(ENABLE_SANITIZER)'
	@echo 'ENABLE_SANITIZER_THREAD = $(ENABLE_SANITIZER_THREAD)'

.PHONY: help
