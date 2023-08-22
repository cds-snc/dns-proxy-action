.PHONY: dev release

dev:
	@echo "Starting dev server..."
	@DNS_PROXY_PORT=8053 DNS_PROXY_OVERWRITECONFIG=false go run .

release:
	@mkdir -p release/latest
	@docker build -t dns-proxy-action-build -f Dockerfile.build .
	@docker create -ti --name dns-proxy-action-build dns-proxy-action-build bash 
	@docker cp dns-proxy-action-build:/dns-proxy-action release/latest/dns-proxy-action
	@docker rm -f dns-proxy-action-build

release-test:
	@mkdir -p release/latest
	@docker build -t dns-proxy-action-build -f Dockerfile.build .
	@docker create -ti --name dns-proxy-action-build dns-proxy-action-build bash 
	@docker cp dns-proxy-action-build:/dns-proxy-action release/latest/dns-proxy-action-test
	@docker rm -f dns-proxy-action-build