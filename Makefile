.PHONY: ci test build vet fmt fmt-check tofu-check ansible-check diff-check

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
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) go build -o bin/homelab ./cmd/homelab

tofu-check:
	tofu fmt -check infra/tofu
	cd infra/tofu && tofu init -backend=false -input=false && tofu validate

ansible-check:
	mkdir -p "$(ANSIBLE_LOCAL_TEMP)" "$(ANSIBLE_REMOTE_TEMP)"
	ANSIBLE_LOCAL_TEMP="$(ANSIBLE_LOCAL_TEMP)" ANSIBLE_REMOTE_TEMP="$(ANSIBLE_REMOTE_TEMP)" ansible-playbook --syntax-check -i localhost, ansible/site.yml

diff-check:
	git diff --check

ci: fmt-check test vet build tofu-check ansible-check diff-check
