.PHONY: dev release release-all release-test test
.DEFAULT_GOAL := release

PLATFORM ?= amd64

dev:
	@echo "Starting dev server..."
	@DNS_PROXY_PORT=8053 DNS_PROXY_OVERWRITECONFIG=false go run .

release:
	@mkdir -p release/latest
	@docker build --platform linux/$(PLATFORM) -t dns-proxy-action-build -f Dockerfile.build .
	@docker create -ti --name dns-proxy-action-build dns-proxy-action-build bash
	@docker cp dns-proxy-action-build:/dns-proxy-action release/latest/dns-proxy-action-$(PLATFORM)
	@docker rm -f dns-proxy-action-build

release-all:
	@$(MAKE) release PLATFORM=amd64
	@$(MAKE) release PLATFORM=arm64

release-test:
	@mkdir -p release/latest
	@docker build --platform linux/$(PLATFORM) -t dns-proxy-action-build -f Dockerfile.build .
	@docker create -ti --name dns-proxy-action-build dns-proxy-action-build bash
	@docker cp dns-proxy-action-build:/dns-proxy-action release/latest/dns-proxy-action-$(PLATFORM)-test
	@docker rm -f dns-proxy-action-build

test:
	@echo "Installing dependencies..."
	@go mod download
	@echo "Running unit tests..."
	@go test ./... -v -timeout 60s