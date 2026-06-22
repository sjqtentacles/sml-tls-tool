# sml-tls-tool build (IMPURE conformance / fuzz harness -- a TOOL, not
# a pure library).
#
#   make                  build socket_shim + bogo_shim (default)
#   make all              build everything: shim, bogo, all AFL harnesses
#   make bin/socket_shim  build the TCP driver CLI
#   make bin/bogo_shim    build the BoGo shim CLI
#   make afl-all          build every AFL harness under bin/afl_*
#   make corpus           regenerate seed corpora from RFC 8448 vectors
#   make clean            remove bin/ and out/
#
# This tool opens real TCP sockets, spawns subprocesses, and reads from
# stdin (AFL). It is NOT part of the dual-compiler deterministic purity
# guarantee of sml-tls; all protocol logic stays in the pure library.

MLTON      ?= mlton
BIN        := bin
TLSDIR     := lib/github.com/sjqtentacles/sml-tls

SHIM_MLB   := cli/socket_shim.mlb
BOGO_MLB   := cli/bogo_shim.mlb

# AFL harness MLBs (one per decoder).
AFL_MLB := \
	fuzz/afl_record.mlb \
	fuzz/afl_ciphertext.mlb \
	fuzz/afl_clienthello.mlb \
	fuzz/afl_serverhello.mlb \
	fuzz/afl_certificate.mlb \
	fuzz/afl_extensions.mlb \
	fuzz/afl_recordprotect.mlb

AFL_BINS := $(patsubst fuzz/%.mlb,$(BIN)/%,$(AFL_MLB))

.PHONY: all afl-all corpus clean

all: $(BIN)/socket_shim $(BIN)/bogo_shim afl-all

# ---- TCP socket driver (client/server) ----
$(BIN)/socket_shim: $(SHIM_MLB) src/socket_shim.sig src/socket_shim.sml \
                    cli/socket_main.sml $(TLSDIR)/sources.mlb | $(BIN)
	$(MLTON) -output $@ $(SHIM_MLB)

# ---- BoGo shim CLI ----
$(BIN)/bogo_shim: $(BOGO_MLB) src/socket_shim.sig src/socket_shim.sml \
                  src/bogo_shim.sig src/bogo_shim.sml cli/bogo_main.sml \
                  $(TLSDIR)/sources.mlb | $(BIN)
	$(MLTON) -output $@ $(BOGO_MLB)

# ---- AFL harnesses ----
# Each per-decoder harness is its own MLB; pattern rule builds them.
$(BIN)/afl_%: fuzz/afl_%.mlb fuzz/afl_harness.sml fuzz/afl_%.sml \
              $(TLSDIR)/sources.mlb | $(BIN)
	$(MLTON) -output $@ $<

afl-all: $(AFL_BINS)

# ---- Seed corpus regeneration ----
corpus:
	python3 scripts/generate_corpus.py

$(BIN):
	mkdir -p $(BIN)

clean:
	rm -rf $(BIN) out
