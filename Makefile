.PHONY: dev reset

dev:
	@echo "Starting dev server..."
	@DNS_PROXY_PORT=8053 DNS_PROXY_OVERWRITECONFIG=false go run .