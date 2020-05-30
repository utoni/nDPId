CC = gcc
CFLAGS = -Wall -Wextra $(EXTRA_CFLAGS)
LIBS = -pthread -lpcap -lm

ifneq ($(CUSTOM_LIBNDPI),)
LIBS += '$(CUSTOM_LIBNDPI)'
else
LIBS += -lndpi
endif

ifeq ($(ENABLE_DEBUG),yes)
CFLAGS += -Og -g3
endif

ifeq ($(ENABLE_SANITIZER),yes)
CFLAGS += -fsanitize=address -fsanitize=undefined -fsanitize=leak
LIBS += -lasan -lubsan
endif

RM = rm -f

main: main.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

clean:
	$(RM) main
