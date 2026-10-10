# Developer entry points. CI runs the same commands (see .github/workflows/ci.yml), so
# "make check" passing locally is what a pull request needs.
#
#   make help        list the targets
#   make check       build + vet + format check + tests + UI script syntax
#   make build       stamped binary in dist/
#   make snapshot    full release build (all platforms) into dist/, nothing published

MODULE   := $(shell go list -m)
VERSION  ?= $(or $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//'),0.0.0-dev)
COMMIT   ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE     ?= $(shell git log -1 --format=%cI 2>/dev/null)
LDFLAGS  := -s -w \
  -X $(MODULE)/internal/version.Version=$(VERSION) \
  -X $(MODULE)/internal/version.Commit=$(COMMIT) \
  -X $(MODULE)/internal/version.Date=$(DATE)
EXE      := $(if $(filter Windows_NT,$(OS)),.exe,)

.DEFAULT_GOAL := help
.PHONY: help clean-stale winres collector build demo test race vet fmt fmt-check lint vuln ui-check check e2e snapshot docker release-notes clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*## "}{printf "  %-14s %s\n", $$1, $$2}'

clean-stale: ## Remove leftovers in dist/ that no current target builds (runs before every build)
	@scripts/clean-stale.sh

winres: ## Windows version information and icon for the two programs (scripts/winres.sh)
	@scripts/winres.sh $(VERSION)

build: clean-stale winres ## Build a stamped, static binary into dist/
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/cipherhorizon$(EXE) ./cmd/cipherhorizon

collector: clean-stale winres ## Build the small endpoint collector (no server, database or scanner) into dist/
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/cipherhorizon-collector$(EXE) ./cmd/cipherhorizon-collector

demo: clean-stale ## Build the development-only demo targets into dist/
	go build -o dist/demo-targets$(EXE) ./cmd/demo-targets

test: ## Run the Go tests
	go test -count=1 ./...

race: ## Run the Go tests with the race detector (needs a C toolchain)
	go test -race -count=1 ./...

vet: ## go vet
	go vet ./...

fmt: ## Format the Go code
	gofmt -w .

fmt-check: ## Fail if any Go file is not gofmt-clean
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; exit 1; fi

lint: ## golangci-lint
	golangci-lint run ./...

vuln: ## Known-vulnerability scan of the dependencies and the code paths that reach them
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

ui-check: ## Syntax-check every UI script (the UI has no build step)
	@for f in $$(find web/static -name '*.js'); do node --check "$$f" || exit 1; done; echo "ui scripts ok"

check: build vet fmt-check test ui-check ## Everything a pull request must pass locally

e2e: build demo ## Browser end-to-end journey (needs Node 22+ and Chrome/Edge); see testing/README.md
	@echo "start dist/demo-targets and 'dist/cipherhorizon serve --allow-loopback --db e2e.db --addr 127.0.0.1:8090', then:"
	@echo "  node testing/e2e/journey.mjs"

snapshot: ## Build every release artifact locally without publishing (needs goreleaser)
	GITHUB_REPOSITORY=$${GITHUB_REPOSITORY:-local/cipherhorizon} goreleaser release --snapshot --clean --skip=sign,sbom

docker: ## Build the container image locally as cipherhorizon:dev
	docker build -t cipherhorizon:dev --build-arg MODULE=$(MODULE) --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) .

release-notes: ## Print the CHANGELOG section for VERSION=x.y.z
	@scripts/release-notes.sh $(VERSION)

clean: ## Remove build output
	rm -rf dist artifacts/screenshots
