# DNS Proxy action

The purpose of this action is to create a DNS pseudo-proxy which allows you to do some basic safe- and block-listing of domains on your Ubuntu GitHub Action runners. It is also able to audit domain resolution requests and forward those to Microsoft Sentinel through an existing Data Collection Endpoint (DCE) and Data Collection Rule (DCR).

## Configuration

The action is configured through the following environment variables:

| Variable | Description | Default value |
| --- | --- | --- |
| `DNS_PROXY_HOST` | The host to listen on | `172.17.0.1` |
| `DNS_PROXY_PORT` | The port to listen on | `53` |
| `DNS_PROXY_SAFELIST` | A comma or newline separated list of domains to allow | |
| `DNS_PROXY_BLOCKLIST` | A comma or newline separated list of domains to block | |
| `DNS_PROXY_UPSTREAMSERVER` | The upstream DNS server to forward requests to | `8.8.8.8` |
| `DNS_PROXY_LOGLEVEL` | The log level to use | `info` |
| `DNS_PROXY_FORWARDTOSENTINEL` | Whether to forward DNS requests to Microsoft Sentinel | `false` |
| `DNS_PROXY_SENTINELTENANTID` | Azure tenant ID used to request access tokens | |
| `DNS_PROXY_SENTINELCLIENTID` | Azure app registration client ID with federated credential for GitHub OIDC | |
| `DNS_PROXY_SENTINELOIDCAUDIENCE` | Audience used when requesting GitHub OIDC token | `api://AzureADTokenExchange` |
| `DNS_PROXY_SENTINELDCEURI` | Existing Data Collection Endpoint ingestion URI (for example `https://<dce>.ingest.monitor.azure.com`) | |
| `DNS_PROXY_SENTINELDCRIMMUTABLEID` | Existing DCR immutable ID | |
| `DNS_PROXY_SENTINELSTREAMNAME` | Stream name defined in the DCR | `Custom-GitHubMetadata_CI_DNS_Queries_V2_CL` |
| `DNS_PROXY_OVERWRITECONFIG` | Whether to overwrite the DNS configuration on the host | `true` |
| `DNS_PROXY_QUERYLOGFILEPATH` | The path to the query log file | `/tmp/dns_query.log` |
| `DNS_PROXY_WILDCARDGREEDY` | `*` character behaviour for safe and block lists (greedy `*` matches zero or more domain labels while non-greedy only matches one label) | `false` |

## Example usage

Blocks all requests to download Terraform from Hashicorp:

```yaml

- name: Start DNS proxy
  uses: cds-snc/dns-proxy-action@main
  env: 
    DNS_PROXY_BLOCKLIST: "releases.hashicorp.com"

- name: Run a composite action
  uses: cds-snc/terraform-tools-setup@v1

```

You can also use safe-listing to allow only a specific set of domains:

```yaml
- name: Start DNS proxy
  uses: cds-snc/dns-proxy-action@main
  env: 
    DNS_PROXY_SAFELIST: "github.com,githubusercontent.com,*.github.com,*.githubusercontent.com"
```

Note that both safe-listing and block-listing can not be used at the same time, but using wildcards is allowed.

Forwarding DNS requests to Microsoft Sentinel using OIDC and an existing DCR/DCE:

```yaml
- name: Start DNS proxy
  uses: cds-snc/dns-proxy-action@main
  env: 
    DNS_PROXY_FORWARDTOSENTINEL: "true"
    DNS_PROXY_SENTINELTENANTID: ${{ vars.AZURE_TENANT_ID }}
    DNS_PROXY_SENTINELCLIENTID: ${{ vars.AZURE_CLIENT_ID }}
    DNS_PROXY_SENTINELDCEURI: ${{ vars.SENTINEL_DCE_URI }}
    DNS_PROXY_SENTINELDCRIMMUTABLEID: ${{ vars.SENTINEL_DCR_IMMUTABLE_ID }}
    DNS_PROXY_SENTINELSTREAMNAME: Custom-GitHubMetadata_CI_DNS_Queries_V2_CL
```

Make sure the workflow grants `id-token: write` permission so the action can request a GitHub OIDC token.

## Migration from legacy Log Analytics auth

This action now uses GitHub OIDC with Microsoft Entra ID and sends records to an existing DCR/DCE endpoint.
The previous shared-key ingestion flow is no longer used.

Environment variable migration:

| Previous variable | New variable(s) | Notes |
| --- | --- | --- |
| `DNS_PROXY_LOGANALYTICSWORKSPACEID` | `DNS_PROXY_SENTINELDCEURI`, `DNS_PROXY_SENTINELDCRIMMUTABLEID`, `DNS_PROXY_SENTINELSTREAMNAME` | Destination is now explicit DCE + DCR stream instead of workspace `/api/logs`. |
| `DNS_PROXY_LOGANALYTICSSHAREDKEY` | None | Shared keys are replaced by OIDC token exchange. |
| `DNS_PROXY_LOGANALYTICSTABLE` | `DNS_PROXY_SENTINELSTREAMNAME` | Use the DCR stream name (for example `Custom-GitHubMetadata_CI_DNS_Queries_V2_CL`). |

New required identity settings when `DNS_PROXY_FORWARDTOSENTINEL=true`:

- `DNS_PROXY_SENTINELTENANTID`
- `DNS_PROXY_SENTINELCLIENTID`
- `DNS_PROXY_SENTINELDCEURI`
- `DNS_PROXY_SENTINELDCRIMMUTABLEID`
- `DNS_PROXY_SENTINELSTREAMNAME`

Optional identity setting:

- `DNS_PROXY_SENTINELOIDCAUDIENCE` (defaults to `api://AzureADTokenExchange`)

Workflow prerequisites:

1. Add `permissions: id-token: write` to the workflow/job using this action.
2. Configure a federated credential on the Azure app registration identified by `DNS_PROXY_SENTINELCLIENTID`.
3. Ensure that app has permission to ingest into the target DCR stream.
4. Reuse existing DCR and DCE from your infrastructure repository; this action does not create or manage them.

## Explanation

The action is a pseudo-proxy because it only performs naive checks on the domain name used in DNS resolution. It has no caching or any of the other goodies that come with a full blown DNS server. Also the patching of the `/etc/resolv.conf` file is not done in a very robust way. It is meant to be used in a GitHub Action runner environment where the `/etc/resolv.conf` file is probably not used for anything else. Hosting the proxy on `172.17.0.1` also forces any Docker containers to use the proxy.

## License
MIT