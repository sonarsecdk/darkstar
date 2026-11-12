# Distributed Scanner Workers

Darkstar can run as an orchestrator plus scanner-only workers.

The orchestrator is the normal web/API container. It owns:

- the frontend
- tenant auth, SSO/MFA and API keys
- the central scan queue
- scanner node registration
- scan logs, lifecycle and locking

Scanner workers run the same scanner tooling without frontend/auth UI. They:

- authenticate with a one-time generated `dscan_...` token
- poll `/api/scanner-workers/jobs/claim`
- atomically claim one queued job
- execute `python3 -m darkstar.main`
- stream logs back to the orchestrator
- write results to the central Darkstar database using the supplied DB connection
- complete the job through the orchestrator API

## Create An Attach Command

Run this on the orchestrator host/container:

```bash
python3 -m darkstar.scanner_attach create \
  --name edge-office \
  --url http://darkstar.local:8080 \
  --max-parallel-jobs 2
```

For a local Compose worker, use the Compose network:

```bash
docker compose exec darkstar-web python3 -m darkstar.scanner_attach create \
  --name local-scanner \
  --url http://darkstar-web:8080 \
  --network darkstar_vuln_net
```

The scanner token is written to a `0600` env file and the printed `docker run`
command references the corresponding host path with `--env-file`. The default
Compose setup stores these files under `./data/scanner-env`. Do not paste the
token into logs or tickets. Revoking the scanner node invalidates it.

## Start A Local Worker

Copy the generated env file values into the worker host's protected `.env`
or use the printed `docker run --env-file ...` command on the host where the
scanner container will run.

```bash
docker compose --profile scanner up -d darkstar-scanner
```

## Remote Worker Notes

Remote workers need outbound access to:

- the orchestrator API URL
- the central MariaDB endpoint, or a VPN/tunnel that exposes it

Create a remote attach command with the database hostname that is reachable
from that worker:

```bash
python3 -m darkstar.scanner_attach create \
  --name customer-edge \
  --url https://darkstar.example \
  --db-host mariadb.internal.example \
  --image registry.example/darkstar:tested
```

Without `--network`, the command refuses local-only database names such as
`mariadb` and `localhost`, because those would point at the worker container
itself rather than the orchestrator database.

This keeps scans running from the remote/internal network while results land in
the central tenant database.

Every scanner node can run every scanner by default. Use `max-parallel-jobs` to
control capacity per worker.

## Dedicated remote ZAP worker

When another application owns a persistent ZAP daemon, give Darkstar a separate
worker and ZAP home. A controller can reset the daemon's session between jobs;
sharing that session can mix reports or remove another application's results.
Darkstar's ZAP integration starts and stops its own local daemon for each job.

Register the worker through the platform-admin scanner API with capabilities
`["zap"]` and `max_parallel_jobs: 1`. The scanner attach CLI currently registers
all capabilities; setting `DARKSTAR_SCANNER_CAPABILITIES=zap` on the worker alone
does not restrict the server's registration. Keep the returned token in a
protected environment file, never in version control.

Use the same tested Darkstar image and source revision as the orchestrator.
Configure these worker environment values in addition to its token and database
credentials:

```dotenv
DARKSTAR_SCANNER_CAPABILITIES=zap
DARKSTAR_WORKER_MAX_PARALLEL=1
DARKSTAR_WORKER_ENV_FILE=/app/.env
ZAP_POLICY_DIR=/app/zap-policies
NUCLEI_TEMPLATES_DIR=/app/disabled-nuclei-templates
OPENVAS_API_URL=http://127.0.0.1:1
PYTHONPATH=/app:/app/darkstar
```

The last two scanner-specific settings avoid unnecessary Nuclei template
enumeration and OpenVAS requests on a ZAP-only appliance.

Mount the environment file at `/app/.env` read-only with host permissions `0600`.
Mount the tested application source at `/app/darkstar` read-only. If using the
server's existing ZAP distribution, copy only its runtime files into a separate
directory and mount that at `/opt/zaproxy` read-only. Do not copy another
controller's work directory, sessions or credentials. Ensure `zap.sh` is on PATH.

Mount the policy source directory at `/app/zap-policies` read-only, and give the
worker its own writable `/root/.ZAP`. Darkstar imports private policy copies;
the administrator's policy files remain unchanged. The catalog refreshes every
five minutes. Imported policy compatibility should be checked with the deployed
ZAP version before accepting jobs.

Remote workers need both API and MariaDB connectivity. A VPN or an SSH tunnel
can provide these. The current database client uses port 3306; a tunnel can map
a differently published database port to port 3306 on the worker host. When
using host-loopback tunnel listeners, the worker needs host networking. Bind
listeners to loopback and use a dedicated, restricted SSH key. Protect API
traffic carrying the scanner token as well as database traffic.

Configure the tunnel as a restarting service and the container with
`--restart unless-stopped`. Choose CPU and memory limits appropriate to the
scanner host. Record the image digest and source commit for future updates:
remote source copies do not automatically follow orchestrator deployments.

Before enabling the worker, check for queued jobs it could immediately claim.
Verify database access, online heartbeats, the ZAP-only catalog, native policy
imports and restart recovery. These checks do not establish that a full scan
can reach its target or save findings. Test scan execution separately against
an authorized test application, including its actual scheme and port.

To disconnect the appliance, stop its container while idle, revoke its scanner
registration in Settings and disable its dedicated tunnel. Existing findings
and other ZAP services can remain intact. A revoked worker needs a new token to
reconnect.
