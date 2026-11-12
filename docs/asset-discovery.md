# Asset discovery and approval

**Approved Assets** separates what Darkstar has found from what an organization
is allowed to scan. Platform administrators can discover and approve assets.
Customers see their organization's approved IPs and domains, with services and
web applications underneath each host. Tenant administrators can start scans;
other members have read-only access to this inventory.

## Discover a target

1. Select the customer's organization and open **Approved Assets**.
2. Open the discovery panel and paste IPs, CIDRs, exact domain names, or HTTP/HTTPS
   URLs, separated by commas or newlines.
3. Start discovery. Darkstar automatically assigns the job to an available
   discovery worker. You do not choose a vulnerability scanner or appliance.
4. Review the detected services, suitable scanner types, and configured
   appliances. Approve the hosts after reviewing those results.

Full TCP discovery is the default for IPs and domains. The optional common-port
preset trades coverage for speed. Vulnerability scanners and their policies are
selected later, when starting a scan of approved assets.

Discovery requires Nmap on the workers providing discovery. Their platform-managed node
registration must include the `discovery` capability; `*` also includes it. A
ZAP-only appliance should be registered with `zap` and `discovery`, and run with
`DARKSTAR_SCANNER_CAPABILITIES=zap,discovery`. Worker heartbeats cannot grant new
capabilities: changing only that environment variable does not update an existing
node's registration. An operator must update its registered capabilities or
attach a new node with the required capabilities.

The existing queue dispatches discovery to a worker with registered discovery
capability and available capacity. The job records which worker actually ran it.
That worker needs network access to the submitted targets. Probe errors are shown
with the results. A scan with no detected services does not prove that the target
was reachable or has no services; filtering and network access may need checking.

For an IP or domain, **All TCP ports** checks ports 1–65535. **Common ports** uses
the smaller fixed list in `darkstar/asset_discovery.py`, including 3000, 8080 and
8443. A complete URL checks its supplied port and path only. Neither mode does
UDP discovery, vulnerability testing, directory brute forcing, or subdomain
enumeration. Service identification sends Nmap's light version probes. HTTP(S)
checks retain the hostname for virtual hosting and TLS SNI; an authentication
response such as HTTP 401 still identifies a web application. Discovery does
not follow HTTP redirects or disable Nmap's default printer-port exclusions.

Each job accepts at most 256 targets and 256 unique resolved addresses. Larger
CIDRs are rejected before expansion. Jobs use bounded DNS lookups, Nmap timeouts
and service counts. The initial TCP port sweep is limited to 200 probes per
second; service identification and HTTP checks use separate time limits. Full
discovery may take several minutes per address. Stop is available on active jobs.

The platform administrator authorizes only the submitted discovery scope.
Darkstar records the actor and an immutable DNS address snapshot with the job.
The worker checks DNS again and refuses a host if it acquires an address outside
that snapshot. Finding a host, port or URL does **not** approve it for subsequent
vulnerability scans. Pending discovery data and logs are visible only to
platform administrators.

## Approve whole hosts

Select the IPs and domains that belong to the customer and approve them. A domain
also requires its current resolved IPs to be covered by explicitly approved IPs
or CIDRs. Newly discovered addresses appear as separate review candidates; select
them together with the domain when appropriate. A future DNS address change
outside approved IP scope blocks scanning until a platform administrator approves
that address.

Approval covers the whole IP or domain across all ports. Services are observations
under a host, not additional approval objects. For example, approving
`10.0.0.10` allows its services on ports 21, 23 and 3000 without three separate
approvals. Approving `app.customer.example` and its IP scope permits ZAP to use
`https://app.customer.example:8443/` without approving port 8443 separately.

The existing **Settings → Allowed scan targets** list remains the authority for
approval. Existing entries appear in Approved Assets even before discovery.
Removing an approval removes the customer's visibility unless another approval
still covers the host. Discovery observations remain available to the platform
administrator. Changes to approvals or scanner access require queued and running
jobs for that organization to finish or stop first.

## Scanner compatibility and access

Compatibility badges are derived from observed services: TCP services suggest
OpenVAS, and responding web applications suggest ZAP and potentially Nuclei web
templates. An IP learned from DNS alone does not prove a service is present.

Each scanner tag also lists the online appliances whose registered capabilities
and installed profiles support it. These matches are computed from the current
catalog, so appliance IDs are not permanently attached to assets. An appliance
tag means a matching scanner is configured there; it does not prove that every
listed appliance can reach that target's network. Scanner access restrictions
remain separate from suitability.

Platform administrators can
separately limit an approved asset to OpenVAS, ZAP, or the Nuclei family. An empty
selection disables scanning for that asset. Assets without a custom selection
retain existing scanner access. Overlapping host, resolved-IP and CIDR rules are
combined restrictively; resetting one host's selection does not bypass an IP or
network restriction. Checks run when scans are queued and again on workers.

Choose approved hosts in the existing scan dialog. For ZAP, Darkstar expands a
host to its discovered web URLs, including ports and paths. An explicit URL or
port remains an explicit choice. A discovered host with no web application
produces an actionable error instead of silently assuming port 80. Hosts without
any discovery history retain the existing default-HTTP behavior.

OpenVAS continues to use host targets and its appliance's policies. Nuclei badges
and permissions are available, but protocol-aware template selection from this
inventory is future work. A compatibility badge does not mean that an appliance
or scanner policy has been configured.

## Refresh behavior and maintenance

Discovery inventory is stored independently of vulnerability findings in two
additive tenant tables: `asset_inventory` and `asset_scanner_settings`. Existing
`allowed_scan_targets` entries are reused for approvals. The existing worker
queue handles discovery jobs; no new service or scheduler is required.

A successful refresh replaces only the services covered by that job. URL-only
and common-port discovery preserve observations outside their scope. Failed
refreshes retain the last known services and show the latest error. Timestamps
identify stale observations; a retained endpoint is not a guarantee that it is
still reachable. The source appliance is a host-level summary, not a separate
origin history for every service.

Discovery jobs are excluded from customer scan history, risk scores and scan
completion notifications. Workers save results through their authenticated job
API; the API validates job ownership, original hosts, address snapshots and
probe coverage before storing results.

To roll back, first finish or stop discovery jobs, then revert the feature's merge
commit and deploy matching application and worker versions. The new tables can
remain in place: older code ignores them. Host approvals remain ordinary allowed
scan targets. Per-asset scanner restrictions are enforced by this feature, so
review those restrictions before rolling back to code that cannot enforce them.
