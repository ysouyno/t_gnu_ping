SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
DEPS = $(wildcard *.h)
TARGET = main

all: $(TARGET)

$(TARGET): $(OBJECTS)
	gcc -o $@ $^

%.o: %.c $(DEPS)
	gcc -g3 -O0 -gdwarf-2 -c $<

.PHONY: clean
clean:
	$(RM) -f $(OBJECTS) $(TARGET)
