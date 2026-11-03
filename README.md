# Sémaphore

Generates an SBOM with **[Syft](https://github.com/anchore/syft)** for every running Docker image, matches it against
the **[Grype](https://github.com/anchore/grype)** vulnerability DB and alerts through **[Apprise](https://github.com/caronc/apprise)**

## Behavior

| When | What happens |
|---|---|
| Stack starts | Every running image without an SBOM gets one, then a scan |
| New container starts with an image not seen before | SBOM + scan ( through Docker events) |
| Every 5 min | Reconcile pass, picks up anything the event stream missed |
| Every 24 h | Grype DB refresh, stored SBOMs get re-matched, alerts for **new** CVEs |

SBOMs are keyed by image ID so restarts and redeploys of the same image are noops.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `APPRISE_URLS` | – | See [Apprise URL Reference](https://appriseit.com/getting-started/universal-syntax/). Gets normal alerts, and urgent ones too unless `APPRISE_URLS_URGENT` is set |
| `APPRISE_URLS_URGENT` | – | Separate destinations for urgent alerts (e.g. phone push) |
| `MIN_SEVERITY` | `High` | Alert threshold for normal findings: `critical`, `high`, `medium`, `low`. Urgent findings always alert |
| `EPSS_THRESHOLD` | `0.1` | EPSS score (0–1) at which a finding becomes urgent |
| `ONLY_FIXED` | `false` | Only alert when an upstream fix exists |
| `SKIP_WONT_FIX` | `true` | Skip findings the distro marks won't-fix (Debian no-dsa/ignored), unless in CISA KEV |
| `RESCAN_INTERVAL_HOURS` | `24` | Re-match SBOMs against a fresh DB |
| `SCAN_ON_PULL` | `false` | Also react to `image pull` events |
| `EXCLUDE_IMAGES` | – | Regex to filter image names |
| `ALERT_MAX_LINES_PER_IMAGE` | `10` | CVE lines listed per image in an alert |
| `ALERT_MAX_CHARS` | `1800` | Body cap |
| `PRUNE_REMOVED_IMAGES` | `true` | Prune SBOMs of deleted images |
| `LOG_LEVEL` | `INFO` | `DEBUG` shows Syft/Grype errors per reference |


## Alert tiers

Each finding is either **urgent** or **normal**, and each tier is sent as its own message.

A finding is urgent when any of these hold, whatever its severity:

- it is in the [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog (exploited in the wild)
- its [EPSS](https://www.first.org/epss/) score is at least `EPSS_THRESHOLD`
- it looks like remote code execution: its CWE is a command/code injection, unsafe deserialization or unrestricted
  upload class, or its description says so, and its CVSS score says no privileges are needed (`PR:N`)

All three come from Grype's own database, so no extra lookups are made. Alert lines show these signals, plus `DoS` for
availability-only bugs:

```
- CVE-2021-42013 [Critical] httpd 2.4.49 (no fix yet) · KEV · EPSS 100% · RCE
```

Findings the distro won't fix (Debian `no-dsa`/`ignored`, Grype fix state `wont-fix`) are not alerted unless they are
in KEV. Set `SKIP_WONT_FIX=false` to alert on them too.

Urgent messages use Apprise's `failure` type and a `🔴 URGENT` title. A finding already reported as normal is reported
again once it becomes urgent, for example when it gets added to KEV.

## Ignoring CVEs

Mount a Grype config at `/config/grype.yaml`:

```yaml
ignore:
  - vulnerability: CVE-2023-12345
  - vulnerability: CVE-2024-0001
    package:
      name: pkg-name-here
```

## Security

The scanner uses [`docker-socket-proxy`](https://github.com/Tecnativa/docker-socket-proxy) which
allows only GET requests on containers, images and events to avoid direct r/w access to the docker socket
## Development

Managed with [uv](https://docs.astral.sh/uv/). Sources live in `src/semaphore/`.

```sh
uv sync                 # create .venv with runtime + dev deps
uv run pytest           # tests
uv run semaphore        # run locally (needs syft, grype and DOCKER_HOST)
```
