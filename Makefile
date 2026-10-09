# DCF-WatchDawg
.PHONY: all gate test check-gate clean
all: gate

gate:
	@if [ -f gate/Makefile ]; then $(MAKE) -s -C gate; else echo "no gate/ yet"; fi

test:
	tests/run.sh

check-gate:
	scripts/check-gate-fresh.sh

clean:
	@if [ -f gate/Makefile ]; then $(MAKE) -s -C gate clean; fi
