# secrets-vault developer tasks. Run `make tools` once to install linters.

GO        ?= go
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BIN       := bin/secrets-vault
PKG       := github.com/Arntek/secrets-vault
FUZZTIME  ?= 30s

# Pinned tool versions. Keep in sync with .github/workflows/*.yml.
GOSEC_VERSION       := v2.30.0
GOVULNCHECK_VERSION := v1.10.0
STATICCHECK_VERSION := 2026.2.2
ACTIONLINT_VERSION  := v1.7.12
GITLEAKS_VERSION    := v8.30.1

# Touch ID (macOS only). The Swift Secure Enclave bridge is built into a
# static library and linked through cgo; Go code sees it only with the
# "touchid" build tag, which this Makefile sets on macOS. Plain `go build`
# and `go test` (and every non-macOS build) compile without it, and
# package touchid then returns ErrUnsupported. NO_TOUCHID=1 opts out.
TOUCHID_DIR := build/touchid
TOUCHID_LIB := $(TOUCHID_DIR)/libsvtouchid.a
TOUCHID_SRC := internal/touchid/swift/TouchIDBridge.swift
TAGS        ?=
TOUCHID_DEPS :=

ifeq ($(shell uname -s),Darwin)
ifneq ($(NO_TOUCHID),1)
TAGS         += touchid
TOUCHID_DEPS := $(TOUCHID_LIB)
MACOSX_DEPLOYMENT_TARGET ?= 13.0
SWIFT_ARCH   := $(shell uname -m)
SWIFT_SDK    := $(shell xcrun --show-sdk-path)
SWIFT_TCLIB  := $(abspath $(dir $(shell xcrun -f swiftc))../lib/swift/macosx)
export MACOSX_DEPLOYMENT_TARGET
export CGO_ENABLED := 1
# Environment flags, not #cgo directives: see internal/touchid/touchid_darwin.go.
export CGO_LDFLAGS := -Wl,-no_warn_duplicate_libraries -L$(CURDIR)/$(TOUCHID_DIR) -lsvtouchid -L$(SWIFT_SDK)/usr/lib/swift -L$(SWIFT_TCLIB) $(CGO_LDFLAGS)
# Command Line Tools (not Xcode) ship a duplicate bridging.modulemap that
# breaks Swift builds; a VFS overlay hides it without touching system files.
# See spikes/phase0-touchid/README.md. Xcode (CI) doesn't need it.
CLT_BRIDGING := /Library/Developer/CommandLineTools/usr/include/swift/bridging.modulemap
ifneq ($(and $(findstring CommandLineTools,$(shell xcode-select -p 2>/dev/null)),$(wildcard $(CLT_BRIDGING))),)
SWIFT_OVERLAY := -vfsoverlay $(TOUCHID_DIR)/overlay.yaml -Xcc -ivfsoverlay -Xcc $(TOUCHID_DIR)/overlay.yaml
endif
endif
endif

TAGFLAG := $(if $(strip $(TAGS)),-tags '$(strip $(TAGS))')

TOOLBIN := $(shell $(GO) env GOPATH)/bin
tool = $(or $(shell command -v $(1) 2>/dev/null),$(TOOLBIN)/$(1))

.PHONY: all build snapshot cross test-packaging touchid-lib touchid-manual test test-short lint fmt fmt-check vet staticcheck gosec vulncheck gitleaks actionlint fuzz tools clean

all: lint test build

build: $(TOUCHID_DEPS)
	$(GO) build $(TAGFLAG) -trimpath -ldflags "-s -w -X $(PKG)/internal/cli.Version=$(VERSION)" -o $(BIN) ./cmd/secrets-vault

test: $(TOUCHID_DEPS)
	$(GO) test $(TAGFLAG) -race -count=1 ./...

test-short: $(TOUCHID_DEPS)
	$(GO) test $(TAGFLAG) -short ./...

# npm installer and the Python / Node script helpers (no network).
test-packaging:
	cd packaging/npm && npm test
	cd helpers/node && npm test
	python3 -I -m unittest discover -s helpers/python -p "test_*.py"

# Local dry run of the release build (no upload). macOS only; needs goreleaser.
snapshot:
	@set -e; for kv in $$(./scripts/swift-env.sh); do export "$$kv"; done; \
	goreleaser release --snapshot --clean --skip=publish

# Non-macOS release targets build without cgo (no Touch ID).
cross:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -o /dev/null ./...
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -o /dev/null ./...
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 $(GO) build -o /dev/null ./...
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) vet ./...
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -o /dev/null ./...

touchid-lib: $(TOUCHID_LIB)

$(TOUCHID_LIB): $(TOUCHID_SRC)
	@mkdir -p $(TOUCHID_DIR)
	@: > $(TOUCHID_DIR)/empty.modulemap
	@printf '{"version":0,"case-sensitive":"false","roots":[{"type":"file","name":"%s","external-contents":"%s"}]}\n' \
		"$(CLT_BRIDGING)" "$(CURDIR)/$(TOUCHID_DIR)/empty.modulemap" > $(TOUCHID_DIR)/overlay.yaml
	xcrun swiftc -parse-as-library -O -static -emit-library -module-name SVTouchID \
		-target $(SWIFT_ARCH)-apple-macos$(MACOSX_DEPLOYMENT_TARGET) \
		$(SWIFT_OVERLAY) $(TOUCHID_SRC) -o $@

# Real Touch ID against the Secure Enclave: someone must touch the sensor.
# Enrolls a throwaway key in a temp folder, then asks for Touch ID twice
# (touch, then cancel). See internal/touchid/touchid_manual_test.go.
touchid-manual: $(TOUCHID_LIB)
	$(GO) test -count=1 -v -tags 'touchid manual' -run '^TestManualTouchID$$' ./internal/touchid

lint: fmt-check vet staticcheck gosec vulncheck gitleaks actionlint

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet $(TAGFLAG) ./...

staticcheck:
	$(call tool,staticcheck) $(TAGFLAG) ./...

gosec:
	$(call tool,gosec) $(TAGFLAG) -quiet ./...

vulncheck:
	$(call tool,govulncheck) $(TAGFLAG) ./...

# Scans git history. CI also runs it on every push with full history.
gitleaks:
	$(call tool,gitleaks) git --redact --no-banner .

actionlint:
	$(call tool,actionlint)

# Runs every FuzzXxx target for FUZZTIME each (nightly CI uses longer).
fuzz:
	./scripts/fuzz.sh $(FUZZTIME)

tools:
	$(GO) install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(GO) install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
	$(GO) install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)
	@command -v gitleaks >/dev/null || echo "Install gitleaks $(GITLEAKS_VERSION): brew install gitleaks"

clean:
	rm -rf bin dist build
