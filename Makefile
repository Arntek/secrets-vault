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

TOOLBIN := $(shell $(GO) env GOPATH)/bin
tool = $(or $(shell command -v $(1) 2>/dev/null),$(TOOLBIN)/$(1))

.PHONY: all build test test-short lint fmt fmt-check vet staticcheck gosec vulncheck gitleaks actionlint fuzz tools clean

all: lint test build

build:
	$(GO) build -trimpath -ldflags "-s -w -X $(PKG)/internal/cli.Version=$(VERSION)" -o $(BIN) ./cmd/secrets-vault

test:
	$(GO) test -race -count=1 ./...

test-short:
	$(GO) test -short ./...

lint: fmt-check vet staticcheck gosec vulncheck gitleaks actionlint

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

staticcheck:
	$(call tool,staticcheck) ./...

gosec:
	$(call tool,gosec) -quiet ./...

vulncheck:
	$(call tool,govulncheck) ./...

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
	rm -rf bin dist
