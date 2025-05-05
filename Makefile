# On Linux, every command that's executed with $(SANDBOX) is executed in a
# bubblewrap container without network access and with limited access to the
# filesystem.

GOPATH ?= $(shell pwd)/.go/path
GOCACHE ?= $(shell pwd)/.go/cache

OUTPUT ?= $(shell pwd)/build/
OUTPUT_RELEASE ?= $(OUTPUT)release/
OUTPUT_TOOLS ?= $(OUTPUT)tools/

MODULE := $(shell grep '^module' go.mod|cut -d' ' -f2)
NAME := $(shell basename $(MODULE))
VERSION := $(shell jq .Version src/metadata/metadata.json 2>/dev/null || echo "0.0.0")

SRC := ./src ./tools
GOFER := go run $(shell pwd)/tools/gofer.go
SANDBOX := $(GOFER) sandbox

# The versions of these tools must match the versions in tools/go.mod.
TOOL_NILERR := $(GOPATH)/pkg/mod/github.com/gostaticanalysis/nilerr@v0.1.1/cmd/nilerr
TOOL_ERRCHECK := $(GOPATH)/pkg/mod/github.com/kisielk/errcheck@v1.6.3
TOOL_REVIVE := $(GOPATH)/pkg/mod/github.com/mgechev/revive@v1.3.2
TOOL_GOSEC := ./tools/gosec.go
TOOL_GOIMPORTS := $(GOPATH)/pkg/mod/golang.org/x/tools@v0.13.0/cmd/goimports
TOOL_STATICCHECK := $(GOPATH)/pkg/mod/honnef.co/go/tools@v0.4.2/cmd/staticcheck

export GOPATH := $(GOPATH)
export GOCACHE := $(GOCACHE)
export CGO_ENABLED := 0
export GO111MODULE := on
export GOFLAGS := -mod=readonly
export GOSUMDB := sum.golang.org
export GOPROXY := off
export REAL_GOPROXY := $(shell go env GOPROXY)

# Unfortunately there is no Go-specific way of pinning the CA for GOPROXY.
export SSL_CERT_FILE := ./go.pem
export SSL_CERT_DIR := /path/does/not/exist/to/pin/ca

export PATH := $(OUTPUT_TOOLS):$(PATH)

define PIN_EXPLANATION
# The checksums for go.sum and go.mod are pinned because `go mod` with
# `-mod=readonly` isn't read-only.  The `go mod` commands will still modify the
# dependency tree if they find it necessary (e.g., to add a missing module or
# module checksum).
#
# Run `make pin` to update this file.
endef
export PIN_EXPLANATION

all: build

download:
	@GOPROXY=$(REAL_GOPROXY) go mod download -x
	@make verify

download-tools:
	@cd tools && GOPROXY=$(REAL_GOPROXY) go mod download -x
	@make verify

tidy:
	@GOPROXY=$(REAL_GOPROXY) go mod tidy
	@$(SANDBOX) go mod verify

tidy-tools:
	@cd tools && GOPROXY=$(REAL_GOPROXY) go mod tidy
	@cd tools && $(SANDBOX) go mod verify

prepare-offline: tidy tidy-tools
	@GOPROXY=$(REAL_GOPROXY) go list -m -json all >/dev/null
	@cd tools && GOPROXY=$(REAL_GOPROXY) go list -m -json all >/dev/null

tools:
	@mkdir -p $(OUTPUT_TOOLS)
	@$(SANDBOX) go build -modfile tools/go.mod -o $(OUTPUT_TOOLS) $(TOOL_NILERR)
	@$(SANDBOX) go build -modfile tools/go.mod -o $(OUTPUT_TOOLS) $(TOOL_ERRCHECK)
	@$(SANDBOX) go build -modfile tools/go.mod -o $(OUTPUT_TOOLS) $(TOOL_REVIVE)
	@$(SANDBOX) go build -modfile tools/go.mod -o $(OUTPUT_TOOLS) $(TOOL_GOSEC)
	@$(SANDBOX) go build -modfile tools/go.mod -o $(OUTPUT_TOOLS) $(TOOL_GOIMPORTS)
	@$(SANDBOX) go build -modfile tools/go.mod -o $(OUTPUT_TOOLS) $(TOOL_STATICCHECK)
	@$(SANDBOX) echo "output stored in $(OUTPUT_TOOLS)"

clean:
	@$(SANDBOX) rm -rfv $(GOCACHE) $(OUTPUT_TOOLS) $(OUTPUT)

distclean:
	@if [ -d "$(GOPATH)" ]; then chmod -R u=rwX "$(GOPATH)" && rm -rfv "$(GOPATH)"; fi
	@$(SANDBOX) git clean -d -f -x

test:
	@$(SANDBOX) mkdir -p $(OUTPUT)
	@$(SANDBOX) go test -v -coverprofile=$(OUTPUT)/.coverage -coverpkg=./... ./...

coverage:
	@$(SANDBOX) go tool cover -func $(OUTPUT)/.coverage

check-nilerr:
	@$(SANDBOX) echo "Running nilerr"
	@$(SANDBOX) nilerr ./...
	@cd tools && $(SANDBOX) nilerr ./...

check-errcheck:
	@$(SANDBOX) echo "Running errcheck"
	@$(SANDBOX) errcheck ./...
	@cd tools && $(SANDBOX) errcheck ./...

check-revive:
	@$(SANDBOX) echo "Running revive"
	@$(SANDBOX) revive -config revive.toml -set_exit_status ./...

check-gosec:
	@$(SANDBOX) echo "Running gosec"
	@$(SANDBOX) gosec -quiet -exclude-dir $(GOPATH) ./...

check-staticcheck:
	@$(SANDBOX) echo "Running staticcheck"
	@$(SANDBOX) staticcheck ./...
	@cd tools && $(SANDBOX) staticcheck ./...

check-vet:
	@$(SANDBOX) echo "Running go vet"
	@$(SANDBOX) go vet ./...

check-fmt:
	@$(SANDBOX) echo "Running gofmt"
	@$(SANDBOX) gofmt -d -l $(SRC)

check-imports:
	@$(SANDBOX) echo "Running goimports"
	@$(SANDBOX) goimports -d -local $(MODULE) -l $(SRC)

check: verify check-nilerr check-errcheck check-revive check-gosec check-staticcheck check-vet check-fmt check-imports

fix-fmt:
	@$(SANDBOX) gofmt -w -l $(SRC)

fix-imports:
	@$(SANDBOX) goimports -w -l -local $(MODULE) $(SRC)

fix: verify fix-fmt fix-imports

pin:
	@$(SANDBOX) echo "$$PIN_EXPLANATION" > go.pin
	@$(SANDBOX) sha256sum go.sum go.mod tools/go.sum tools/go.mod >> go.pin
	@test -f /etc/ssl/certs/GTS_Root_R1.pem && test -f /etc/ssl/certs/GTS_Root_R4.pem && \
		cat /etc/ssl/certs/GTS_Root_R1.pem /etc/ssl/certs/GTS_Root_R4.pem > go.pem || true

verify:
	@$(SANDBOX) sha256sum --strict --check go.pin
	@if [ -d $(GOPATH) ]; then $(SANDBOX) go mod verify; fi
	@if [ -d $(GOPATH) ]; then cd tools && $(SANDBOX) go mod verify; fi

qa: check test coverage

.PHONY: all download download-tools tidy tidy-tools tools clean distclean
.PHONY: test coverage prepare-offline
.PHONY: check-nilerr check-errcheck check-revive check-gosec check-staticcheck check-vet check-fmt check-imports check
.PHONY: fix-imports fix-fmt fix pin verify qa
