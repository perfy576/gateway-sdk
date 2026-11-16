.DEFAULT_GOAL := all
.PHONY: all deps test check examples install clean help
all deps test check examples install clean help:
	+$(MAKE) -C cpp-sdk $@
