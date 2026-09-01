BINARY_NAME = ensphere
SEEDS_DIR   = ./assets/seeds
EMBED_DIR   = ./cli/internal/payloads/data
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build copy-seeds verify-generated clean install install-all test smoke

build: copy-seeds
	cd cli && go build -ldflags "-X github.com/srank/ensphere/cmd.version=$(VERSION)" -o ../bin/$(BINARY_NAME) .

# copy-seeds mirrors the payload YAML into the payloads package so go:embed can
# reach it (embed cannot reference files outside the Go module). assets/seeds is
# the source of truth; the copy under cli/internal/payloads/data is generated.
copy-seeds:
	rm -f $(EMBED_DIR)/*.yaml
	cp $(SEEDS_DIR)/*.yaml $(EMBED_DIR)/

verify-generated: copy-seeds
	@git ls-files --error-unmatch $(EMBED_DIR)/*.yaml >/dev/null 2>&1 || (echo "generated seed copy is not tracked: $(EMBED_DIR)"; exit 1)
	git diff --exit-code -- $(EMBED_DIR)
	@test -z "$$(git ls-files --others --exclude-standard -- $(EMBED_DIR))" || (echo "untracked generated seeds:"; git ls-files --others --exclude-standard -- $(EMBED_DIR); exit 1)

install: build
	cp bin/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)

install-all: install
	./install-skills.sh

clean:
	rm -rf bin/
	rm -f cli/$(BINARY_NAME)
	rm -rf cli/.gocache/
	rm -f evidence.jsonl evidence.jsonl.lock
	rm -rf ensphere-pentest/

test:
	cd cli && go vet ./...
	cd cli && go test ./...

smoke: build
	./bin/$(BINARY_NAME) --version >/dev/null
	./bin/$(BINARY_NAME) payloads sqli --db postgres --technique blind_time --limit 1 >/dev/null
	./bin/$(BINARY_NAME) payloads sqli --db sqlite --technique blind_boolean --limit 1 >/dev/null
	./bin/$(BINARY_NAME) compliance --list >/dev/null
	./bin/$(BINARY_NAME) cvss --av N --ac L --at N --pr N --ui N --vc H --vi H --va H --sc H --si H --sa H >/dev/null
	@echo "smoke ok"
