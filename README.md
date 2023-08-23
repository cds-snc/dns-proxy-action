# DNS Proxy action

The purpose of this action is to create a DNS pseudo-proxy which allows you to do some basic safe- and block-listing of domains on your Ubuntu GitHub Action runners. It is also able to audit domain resolution requests and forward those to Microsoft Sentinel through a Log Analytics workspace.

## Configuration

The action is configured through the following environment variables:

| Variable | Description | Default value |
| --- | --- | --- |
| `DNS_PROXY_HOST` | The host to listen on | `172.17.0.1` |
| `DNS_PROXY_LISTEN_PORT` | The port to listen on | `53` |
| `DNS_PROXY_SAFE_LIST` | A comma-separated list of domains to allow | |
| `DNS_PROXY_BLOCK_LIST` | A comma-separated list of domains to block | |
| `DNS_PROXY_UPSTREAM` | The upstream DNS server to forward requests to | `8.8.8.8` |
| `DNS_PROXY_LOGLEVEL` | The log level to use | `info` |
| `DNS_PROXY_FORWARDTOSENTINEL` | Whether to forward DNS requests to Microsoft Sentinel | `false` |
| `DNS_PROXY_LOGANALYTICSWORKSPACEID` | The ID of the Log Analytics workspace to forward DNS requests to | |
| `DNS_PROXY_LOGANALYTICSSHAREDKEY` | The key of the Log Analytics workspace to forward DNS requests to | |
| `DNS_PROXY_LOGANALYTICSTABLE` | The name of the Log Analytics table to forward DNS requests to | `GitHubMetadata_CI_DNS_Queries` |
| `DNS_PROXY_OVERWRITECONFIG` | Whether to overwrite the DNS configuration on the host | `true` |
| `DNS_PROXY_QUERYLOGFILEPATH` | The path to the query log file | `/tmp/dns-proxy-query.log` |

## Example usage

Blocks all requests to download Terraform from Hashicorp:

```yaml

- name: Start DNS proxy
  uses: cds-snc/dns-proxy-action@main
  env: 
    DNS_PROXY_BLOCK_LIST: "releases.hashicorp.com"

- name: Run a composite action
  uses: cds-snc/terraform-tools-setup@v1

```

You can also use safe-listing to allow only a specific set of domains:

```yaml
- name: Start DNS proxy
  uses: cds-snc/dns-proxy-action@main
  env: 
    DNS_PROXY_SAFE_LIST: "github.com,githubusercontent.com,*.github.com,*.githubusercontent.com"
```

Note that both safe-listing and block-listing can not be used at the same time, but using wildcards is allowed.

Forwarding DNS requests to Microsoft Sentinel:

```yaml
- name: Start DNS proxy
  uses: cds-snc/dns-proxy-action@main
  env: 
    DNS_PROXY_FORWARDTOSENTINEL: "true"
    DNS_PROXY_LOGANALYTICSWORKSPACEID: ${{ secrets.LOG_ANALYTICS_WORKSPACE_ID }}
    DNS_PROXY_LOGANALYTICSSHAREDKEY: ${{ secrets.LOG_ANALYTICS_SHARED_KEY }}
```

## Explanation

The action is a pseudo-proxy because it only performs naive checks on the domain name used in DNS resolution. It has no caching or any of the other goodies that come with a full blown DNS server. Also the patching of the `/etc/resolv.conf` file is not done in a very robust way. It is meant to be used in a GitHub Action runner environment where the `/etc/resolv.conf` file is probably not used for anything else. Hosting the proxy on `172.17.0.1` also forces any Docker containers to use the proxy.

## License
MIT