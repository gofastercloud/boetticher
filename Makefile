.PHONY: ci test build release-bundle companion-binary companion-check vet fmt fmt-check ansible-check security-check actionlint vuln-check naming-check diff-check schema schema-check image-check image-base image-dns-blocky image-logging image-monitoring image-firewall image-tailnet-router image-airvpn image-bifrost image-printer image-arr image-aiops image-gatus image-network-probe images local-builder-init local-image local-images local-image-scan scan-images scan-base scan-dns-blocky scan-logging scan-monitoring scan-firewall scan-tailnet-router scan-airvpn scan-bifrost scan-printer scan-arr scan-aiops scan-gatus scan-network-probe command-docs command-docs-check deadcode race streamdeck-check

GOCACHE ?= /tmp/boetticher-gocache
GOMODCACHE ?= /tmp/boetticher-gomodcache
ANSIBLE_LOCAL_TEMP ?= /tmp/boetticher-ansible-tmp
ANSIBLE_REMOTE_TEMP ?= /tmp/boetticher-ansible-tmp
UV_CACHE_DIR ?= /tmp/boetticher-uv-cache
RELEASE_VERSION ?= 0.5.1
LOCAL_IMAGE_TARGET ?= image-base
LOCAL_IMAGE_TARGETS ?= image-base
LOCAL_SCAN_TARGET ?= scan-base

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

companion-check:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o /tmp/boetticher-streamdeck-linux-arm64-check ./cmd/boetticher-streamdeck

usb-export-test:
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s ansible/roles/usb-export-host/tests -p 'test_*.py' -v
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s ansible/roles/network-probe-host/tests -p 'test_*.py' -v

vet:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go vet ./...

build:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go build -o bin/boetticher ./cmd/boetticher

release-bundle: companion-binary
	@test -n "$(OUTPUT)" -a -n "$(SOURCE_COMMIT)" -a -n "$(WORKFLOW)" -a -n "$(KEY_ID)" -a -n "$(PRIVATE_KEY)"
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run ./cmd/release-bundle -output "$(OUTPUT)" -release "$(RELEASE_VERSION)" -source-commit "$(SOURCE_COMMIT)" -workflow "$(WORKFLOW)" -key-id "$(KEY_ID)" -private-key "$(PRIVATE_KEY)"

companion-binary:
	mkdir -p bin
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o bin/boetticher-streamdeck-linux-arm64 ./cmd/boetticher-streamdeck

ansible-check:
	mkdir -p "$(ANSIBLE_LOCAL_TEMP)" "$(ANSIBLE_REMOTE_TEMP)"
	ANSIBLE_LOCAL_TEMP="$(ANSIBLE_LOCAL_TEMP)" ANSIBLE_REMOTE_TEMP="$(ANSIBLE_REMOTE_TEMP)" ansible-playbook --syntax-check -i ansible/inventory.syntax.ini ansible/site.yml
	ANSIBLE_LOCAL_TEMP="$(ANSIBLE_LOCAL_TEMP)" ANSIBLE_REMOTE_TEMP="$(ANSIBLE_REMOTE_TEMP)" ansible-playbook --syntax-check -i ansible/inventory.kiosk.syntax.ini ansible/companion.yml

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

deadcode:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run golang.org/x/tools/cmd/deadcode@v0.47.0 -test ./...

local-builder-init:
	./scripts/local-builder.sh init

local-image:
	./scripts/local-builder.sh build "$(LOCAL_IMAGE_TARGET)"

local-images:
	./scripts/local-builder.sh build images $(LOCAL_IMAGE_TARGETS)

local-image-scan:
	./scripts/local-builder.sh scan "$(LOCAL_SCAN_TARGET)"

image-check:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test ./internal/artifacts
	sh -n scripts/benchmark-artifact-compression.sh scripts/build-images.sh scripts/scan-images.sh scripts/local-builder.sh scripts/local-builder-setup.sh scripts/install-debian-archive-keyring.sh scripts/native-builder-run.sh scripts/smoke-appliance.sh scripts/smoke-firewall-image.sh images/base/first-boot/boetticher-first-boot.sh images/base/runtime/install-runtime-state.sh
	@test -z "$$(rg -n 'BOETTICHER_IMAGE_BUILD_COMMAND|exec sh -c' scripts || true)"

image-base image-dns-blocky image-logging image-monitoring image-firewall image-tailnet-router image-airvpn image-bifrost image-printer image-arr image-aiops image-gatus image-network-probe images:
	./scripts/build-images.sh $@

scan-base scan-dns-blocky scan-logging scan-monitoring scan-firewall scan-tailnet-router scan-airvpn scan-bifrost scan-printer scan-arr scan-aiops scan-gatus scan-network-probe scan-images:
	./scripts/scan-images.sh $@

naming-check:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test ./internal/naming

actionlint:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7

vuln-check:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

security-check: naming-check actionlint vuln-check

ci: fmt-check image-check schema-check command-docs-check deadcode test usb-export-test race streamdeck-check companion-check vet build ansible-check security-check diff-check
