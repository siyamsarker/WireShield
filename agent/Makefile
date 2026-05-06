# WireShield Agent Makefile
#
# Targets:
#   make            — build a local binary (same OS/arch as the host)
#   make test       — run Go unit tests
#   make vet        — go vet ./...
#   make dist       — static cross-compiles for linux-amd64 and linux-arm64,
#                     each with a .sha256 sidecar, into ./dist/bin/<arch>/
#   make install    — copies ./dist/bin into the VPN server's AGENT_BINARY_DIR
#                     (set AGENT_BINARY_DIR on the make call)
#   make clean      — remove build outputs
#
# Reproducible builds:
#   - CGO_ENABLED=0 so the binary is fully static (no libc dep)
#   - -trimpath strips local filesystem paths from the binary
#   - -ldflags "-s -w" strips the symbol + DWARF tables (~2 MB smaller)
#   - -buildvcs=false keeps the binary byte-identical across fresh vs. dirty
#     checkouts (the VCS stamping bloats the file otherwise)

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := build

MODULE       := github.com/siyamsarker/wireshield/agent
CMD_PKG      := ./cmd/wireshield-agent
BINARY       := wireshield-agent
VERSION      ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
DIST_DIR     := dist/bin
ARCHES       := linux-amd64 linux-arm64

LDFLAGS      := -s -w -X main.Version=$(VERSION)
BUILDFLAGS   := -trimpath -buildvcs=false
GO           ?= go

# Optional Ed25519 release public key embedded into the agent binary.
# When set, the agent verifies update manifests against this key and refuses
# to upgrade from an unsigned/forged manifest. Generate the keypair offline
# with `make gen-release-key` and pass the hex-encoded public half here.
#
# Example:
#   make dist RELEASE_PUBKEY=ab32f1...64charsofhex
RELEASE_PUBKEY ?=
ifneq ($(strip $(RELEASE_PUBKEY)),)
LDFLAGS += -X main.ReleasePublicKey=$(RELEASE_PUBKEY)
endif

.PHONY: build test vet clean dist install help gen-release-key sign-manifest wsmanifest

help:
	@awk '/^# / { sub(/^# ?/, ""); print }' $(MAKEFILE_LIST) | head -20

# Dev build for the current host.
build:
	$(GO) build $(BUILDFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD_PKG)
	@echo "built ./$(BINARY) version=$(VERSION)"

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

dist: $(ARCHES:%=dist-%)
	@echo
	@echo "dist artefacts:"
	@find $(DIST_DIR) -type f -printf "  %p (%s bytes)\n" 2>/dev/null || find $(DIST_DIR) -type f -exec ls -l {} \;

# Pattern rule: dist-linux-amd64, dist-linux-arm64, ...
# Output naming convention: <binary>_<os>_<arch>  e.g. wireshield-agent_linux_amd64
dist-%:
	@mkdir -p $(DIST_DIR)
	@echo "→ $*"
	@os=$$(echo $* | cut -d- -f1); arch=$$(echo $* | cut -d- -f2); \
		fname="$(BINARY)_$${os}_$${arch}"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
		$(GO) build $(BUILDFLAGS) -ldflags "$(LDFLAGS)" \
			-o $(DIST_DIR)/$$fname $(CMD_PKG); \
		(sha256sum $(DIST_DIR)/$$fname > $(DIST_DIR)/$$fname.sha256 2>/dev/null || \
		 shasum -a 256 $(DIST_DIR)/$$fname > $(DIST_DIR)/$$fname.sha256); \
		chmod 0755 $(DIST_DIR)/$$fname

# Copy dist tree + systemd unit + install.sh into AGENT_BINARY_DIR on this
# host (used on the VPN server after `make dist`). Idempotent; overwrites.
install:
	@test -n "$(AGENT_BINARY_DIR)" || { echo "AGENT_BINARY_DIR is required" >&2; exit 1; }
	@test -d "$(DIST_DIR)" || { echo "run 'make dist' first" >&2; exit 1; }
	install -d -m 0755 "$(AGENT_BINARY_DIR)"
	cp -r $(DIST_DIR)/* "$(AGENT_BINARY_DIR)/"
	install -m 0644 dist/wireshield-agent.service "$(AGENT_BINARY_DIR)/wireshield-agent.service"
	install -m 0755 dist/install.sh "$(AGENT_BINARY_DIR)/install.sh"
	@echo "installed dist tree + unit + installer under $(AGENT_BINARY_DIR)"

clean:
	rm -rf $(BINARY) dist/bin wsmanifest

# Build the operator's manifest signing helper. Run on the (offline)
# signing host that holds the release private key.
wsmanifest:
	$(GO) build $(BUILDFLAGS) -o wsmanifest ./cmd/wsmanifest
	@echo "built ./wsmanifest"

# Generate an Ed25519 release keypair. Writes the private half to
# ./release.key (mode 0600) and the public half (hex) to ./release.pub.
# Run this ONCE per WireShield deployment, store release.key on an
# air-gapped signing host, and pass the contents of release.pub as
# RELEASE_PUBKEY to subsequent `make dist`.
gen-release-key: wsmanifest
	./wsmanifest --gen-key --out-priv release.key --out-pub release.pub
	@echo
	@echo "  Private key (KEEP OFFLINE):  $(PWD)/release.key"
	@echo "  Public key  (embed in agent): $(PWD)/release.pub"
	@echo
	@echo "  To build a signature-verifying agent:"
	@echo "    make dist RELEASE_PUBKEY=\$$(cat release.pub)"

# Sign a manifest in-place. Reads version.json (or MANIFEST=path) and
# writes back the same file with a 'signature' field appended.
sign-manifest: wsmanifest
	@test -n "$(MANIFEST)" || { echo "usage: make sign-manifest MANIFEST=path/to/version.json [PRIV_KEY=path]" >&2; exit 1; }
	./wsmanifest --sign --priv $(or $(PRIV_KEY),release.key) --manifest $(MANIFEST)
