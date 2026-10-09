# gate/Makefile -- builds dcf-gate from the vendored C. No exsc, no fasmg.
CC      ?= gcc
CFLAGS  ?= -O2
HARDEN  := -std=c11 -Wall -Wextra -Werror -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
LDFLAGS += -pie -Wl,-z,relro,-z,now

dcf-gate: dcf-gate.c dcf_net_gate.gen.c dcf_net_gate.gen.h
	$(CC) $(CFLAGS) $(HARDEN) -I. -c dcf-gate.c -o dcf-gate.o
	$(CC) $(CFLAGS) $(HARDEN) -Wno-unused-function -I. -c dcf_net_gate.gen.c -o dcf_net_gate.gen.o
	$(CC) $(CFLAGS) $(HARDEN) $(LDFLAGS) dcf-gate.o dcf_net_gate.gen.o -o $@
	./dcf-gate selftest

.PHONY: clean
clean:
	rm -f dcf-gate dcf-gate.o dcf_net_gate.gen.o
