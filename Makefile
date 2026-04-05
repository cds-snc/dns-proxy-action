.PHONY: dev release release-test test
.DEFAULT_GOAL := release

dev:
	@echo "Starting dev server..."
	@DNS_PROXY_PORT=8053 DNS_PROXY_OVERWRITECONFIG=false go run .

release:
	@mkdir -p release/latest
	@docker build --platform linux/amd64 -t dns-proxy-action-build -f Dockerfile.build .
	@docker create -ti --name dns-proxy-action-build dns-proxy-action-build bash
	@docker cp dns-proxy-action-build:/dns-proxy-action release/latest/dns-proxy-action-amd64
	@docker rm -f dns-proxy-action-build
	@docker build --platform linux/arm64 -t dns-proxy-action-build -f Dockerfile.build .
	@docker create -ti --name dns-proxy-action-build dns-proxy-action-build bash
	@docker cp dns-proxy-action-build:/dns-proxy-action release/latest/dns-proxy-action-arm64
	@docker rm -f dns-proxy-action-build

release-test:
	@mkdir -p release/latest
	@docker build --platform linux/amd64 -t dns-proxy-action-build -f Dockerfile.build .
	@docker create -ti --name dns-proxy-action-build dns-proxy-action-build bash
	@docker cp dns-proxy-action-build:/dns-proxy-action release/latest/dns-proxy-action-amd64-test
	@docker rm -f dns-proxy-action-build
	@docker build --platform linux/arm64 -t dns-proxy-action-build -f Dockerfile.build .
	@docker create -ti --name dns-proxy-action-build dns-proxy-action-build bash
	@docker cp dns-proxy-action-build:/dns-proxy-action release/latest/dns-proxy-action-arm64-test
	@docker rm -f dns-proxy-action-build

test:
	@echo "Installing dependencies..."
	@go mod download
	@echo "Running unit tests..."
	@go test ./... -v -timeout 60s