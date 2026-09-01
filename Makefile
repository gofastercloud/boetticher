.PHONY: ci test build vet fmt fmt-check ansible-check security-check actionlint vuln-check naming-check diff-check schema schema-check image-check image-base image-dns-blocky image-logging image-monitoring image-firewall image-portal image-tailnet-router image-airvpn image-bifrost image-printer image-streamdeck image-aiops image-gatus image-network-probe images scan-images scan-base scan-dns-blocky scan-logging scan-monitoring scan-firewall scan-portal scan-tailnet-router scan-airvpn scan-bifrost scan-printer scan-streamdeck scan-aiops scan-gatus scan-network-probe command-docs command-docs-check race streamdeck-check

GOCACHE ?= /tmp/boetticher-gocache
GOMODCACHE ?= /tmp/boetticher-gomodcache
ANSIBLE_LOCAL_TEMP ?= /tmp/boetticher-ansible-tmp
ANSIBLE_REMOTE_TEMP ?= /tmp/boetticher-ansible-tmp
UV_CACHE_DIR ?= /tmp/boetticher-uv-cache

fmt:
	gofmt -w cmd internal

fmt-check:
	@test -z "$$(gofmt -l cmd internal)"

test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test ./...

race:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test -race ./internal/aiops ./cmd/boetticher-aiops

streamdeck-check:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test ./internal/streamdeck ./cmd/boetticher-streamdeck
	UV_CACHE_DIR=$(UV_CACHE_DIR) uv run --project pi/streamdeck --frozen --with pytest pytest pi/streamdeck/tests

usb-export-test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s ansible/roles/usb-export-host/tests -p 'test_*.py' -v
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s ansible/roles/network-probe-host/tests -p 'test_*.py' -v

vet:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go vet ./...

build:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go build -o bin/boetticher ./cmd/boetticher

ansible-check:
	mkdir -p "$(ANSIBLE_LOCAL_TEMP)" "$(ANSIBLE_REMOTE_TEMP)"
	ANSIBLE_LOCAL_TEMP="$(ANSIBLE_LOCAL_TEMP)" ANSIBLE_REMOTE_TEMP="$(ANSIBLE_REMOTE_TEMP)" ansible-playbook --syntax-check -i ansible/inventory.syntax.ini ansible/site.yml
	ANSIBLE_LOCAL_TEMP="$(ANSIBLE_LOCAL_TEMP)" ANSIBLE_REMOTE_TEMP="$(ANSIBLE_REMOTE_TEMP)" ansible-playbook --syntax-check -i ansible/inventory.kiosk.syntax.ini ansible/kiosk.yml

diff-check:
	git diff --check

schema:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run ./cmd/schema -embedded-output internal/schema/site.schema.json

schema-check: schema
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run ./cmd/schema -output /tmp/boetticher-site.schema.json -embedded-output /tmp/boetticher-embedded-site.schema.json
	cmp -s /tmp/boetticher-site.schema.json schemas/site.schema.json
	cmp -s /tmp/boetticher-site.schema.json internal/schema/site.schema.json

command-docs:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run ./cmd/command-docs > docs/commands.md

command-docs-check:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run ./cmd/command-docs > /tmp/boetticher-commands.md
	cmp -s /tmp/boetticher-commands.md docs/commands.md

image-check:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test ./internal/artifacts
	sh -n scripts/benchmark-artifact-compression.sh scripts/build-images.sh scripts/scan-images.sh scripts/smoke-appliance.sh scripts/smoke-firewall-image.sh images/base/first-boot/boetticher-first-boot.sh images/base/runtime/install-runtime-state.sh
	@test -z "$$(rg -n 'BOETTICHER_IMAGE_BUILD_COMMAND|exec sh -c' scripts || true)"

image-base image-dns-blocky image-logging image-monitoring image-firewall image-portal image-tailnet-router image-airvpn image-bifrost image-printer image-streamdeck image-aiops image-gatus image-network-probe images:
	./scripts/build-images.sh $@

scan-base scan-dns-blocky scan-logging scan-monitoring scan-firewall scan-portal scan-tailnet-router scan-airvpn scan-bifrost scan-printer scan-streamdeck scan-aiops scan-gatus scan-network-probe scan-images:
	./scripts/scan-images.sh $@

naming-check:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test ./internal/naming

actionlint:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7

vuln-check:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

security-check: naming-check actionlint vuln-check

ci: fmt-check image-check schema-check command-docs-check test usb-export-test race streamdeck-check vet build ansible-check security-check diff-check
