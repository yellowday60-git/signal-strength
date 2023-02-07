LDLIBS=-lpcap

all: signal-strength

signal-strength: mac.o main.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f signal-strength *.o