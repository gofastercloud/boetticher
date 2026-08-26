.PHONY: ci test build vet fmt fmt-check tofu-check ansible-check security-check actionlint vuln-check naming-check diff-check schema schema-check image-check image-base image-dns-blocky image-dns-adguard image-logging image-monitoring image-firewall image-portal images scan-images scan-base scan-dns-blocky scan-dns-adguard scan-logging scan-monitoring scan-firewall scan-portal

GOCACHE ?= /tmp/boetticher-gocache
GOMODCACHE ?= /tmp/boetticher-gomodcache
ANSIBLE_LOCAL_TEMP ?= /tmp/boetticher-ansible-tmp
ANSIBLE_REMOTE_TEMP ?= /tmp/boetticher-ansible-tmp

fmt:
	gofmt -w cmd internal

fmt-check:
	@test -z "$$(gofmt -l cmd internal)"

test:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test ./...

vet:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go vet ./...

build:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go build -o bin/boetticher ./cmd/boetticher

tofu-check:
	tofu fmt -check infra/tofu
	cd infra/tofu && tofu init -backend=false -input=false && tofu validate

ansible-check:
	mkdir -p "$(ANSIBLE_LOCAL_TEMP)" "$(ANSIBLE_REMOTE_TEMP)"
	ANSIBLE_LOCAL_TEMP="$(ANSIBLE_LOCAL_TEMP)" ANSIBLE_REMOTE_TEMP="$(ANSIBLE_REMOTE_TEMP)" ansible-playbook --syntax-check -i ansible/inventory.syntax.ini ansible/site.yml

diff-check:
	git diff --check

schema:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run ./cmd/schema

schema-check: schema
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run ./cmd/schema -output /tmp/boetticher-site.schema.json
	cmp -s /tmp/boetticher-site.schema.json schemas/site.schema.json

image-check:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test ./internal/artifacts
	sh -n scripts/build-images.sh scripts/scan-images.sh scripts/smoke-appliance.sh scripts/smoke-firewall-image.sh
	@test -z "$$(rg -n 'BOETTICHER_IMAGE_BUILD_COMMAND|exec sh -c' scripts || true)"

image-base image-dns-blocky image-dns-adguard image-logging image-monitoring image-firewall image-portal images:
	./scripts/build-images.sh $@

scan-base scan-dns-blocky scan-dns-adguard scan-logging scan-monitoring scan-firewall scan-portal scan-images:
	./scripts/scan-images.sh $@

naming-check:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go test ./internal/naming

actionlint:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7

vuln-check:
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

security-check: naming-check actionlint vuln-check

ci: fmt-check image-check schema-check test vet build tofu-check ansible-check security-check diff-check
