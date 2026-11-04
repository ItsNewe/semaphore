
# Sémaphore

Generates an SBOM with **[Syft](https://github.com/anchore/syft)** for every running Docker image, matches it against
the **[Grype](https://github.com/anchore/grype)** vulnerability DB and alerts through **[Apprise](https://github.com/caronc/apprise)**

[demo.webm](https://github.com/user-attachments/assets/65522b9d-5ea1-4c85-93d4-c7e3aa9b593d)

## Behavior

| When | What happens |
|---|---|
| Stack starts | Every running image without an SBOM gets one, then a scan |
| New container starts with an image not seen before | SBOM + scan ( through Docker events) |
| Every 5 min | Reconcile pass, picks up anything the event stream missed |
| Every 24 h | Grype DB refresh, stored SBOMs get re-matched, alerts for **new** CVEs |
| Each scan of a vulnerable image | [Update check](#fixing-updates): newer upstream image that fixes its CVEs? |

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
| `SKIP_DISPUTED` | `true` | Skip CVEs whose NVD description is marked `** DISPUTED **`, unless in CISA KEV |
| `SKIP_NEGLIGIBLE` | `true` | Skip findings of `Negligible` severity, even urgent ones, unless in CISA KEV |
| `RESCAN_SCHEDULE` | `0 0 * * *` | Cron expression (5 fields, local time per `TZ`) to re-match SBOMs against a fresh DB |
| `SCAN_ON_PULL` | `false` | Also react to `image pull` events |
| `SCAN_WORKERS` | `2` | Images scanned in parallel |
| `EXCLUDE_IMAGES` | – | Regex to filter image names |
| `ALERT_MAX_LINES_PER_IMAGE` | `5` | CVE lines listed per image in an alert, most important first (KEV, RCE, severity, EPSS) |
| `ALERT_MAX_CHARS` | `1800` | Body cap |
| `PRUNE_REMOVED_IMAGES` | `true` | Prune SBOMs of deleted images |
| `CHECK_UPDATES` | `true` | Look for a newer image that fixes the findings, see [Fixing updates](#fixing-updates) |
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
**httpd:2.4.49** (web) · new image
Critical: 1 | High: 2 | RCE: 1 | KEV: 1
- [CVE-2021-42013](https://nvd.nist.gov/vuln/detail/CVE-2021-42013) [Critical] httpd 2.4.49 · KEV · EPSS 100% · RCE
```

Findings the distro won't fix (Debian `no-dsa`/`ignored`, Grype fix state `wont-fix`) are not alerted unless they are
in KEV. Set `SKIP_WONT_FIX=false` to alert on them too. Disputed CVEs (`SKIP_DISPUTED`) and `Negligible`
ones (`SKIP_NEGLIGIBLE`) are handled the same way. Skipped findings still show, grayed, in the TUI's CVE list.

Urgent messages use Apprise's `failure` type and a `🔴 URGENT` title. A finding already reported as normal is reported
again once it becomes urgent, for example when it gets added to KEV.

## Fixing updates

For every image with alertable findings, semaphore looks for two candidates in the registry with
[crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane):

- **rebuilt**: the running tag now points to a different digest upstream (e.g. `nginx:1.27` got a patched base)
- **newer tag**: the highest tag in the same line with the same suffix, `1.27.3-alpine` → `1.27.5-alpine`,
  `3.12-slim` → `3.14-slim`. Major bumps aren't suggested, and tags like `latest` only get the rebuild check

Each candidate is SBOM'd straight from the registry (no `docker pull`), and its SBOM is cached by digest, so
later checks only re-match it. The candidate fixing the most findings is kept. It shows up as:

- a `⬆ nginx:1.27.5 fixes 7/9` line under the image in alerts, and `· ⬆ fixed` on each fixed finding
- one `⬆ 1 fixing update available` message (normal tier), sent once per candidate digest
- `update` in `summary.json`, and the **Images** tab of the TUI, with the severity counts once applied

Images built locally (no registry digest) are skipped. For private registries, mount a Docker `config.json`
and point `DOCKER_CONFIG` at its directory. crane and syft both read it.

## TUI

```sh
docker exec -it semaphore semaphore-tui
```

- **Settings**: `MIN_SEVERITY`, `EPSS_THRESHOLD` and `RESCAN_SCHEDULE`
- **Targets**: Apprise URLs and which tiers (urgent, normal) each one receives
- **Resend**: re-sends the latest notification batch to the saved targets
- **Images**: every scanned image with its scan time, counts (`C:2 | H:5`), fixing update and counts once applied.
  **Rescan selected** / **Rescan all** (after a confirmation) discard the SBOMs, results and alert history, so the
  daemon rescans them as new and alerts every current finding again
- **Test**: sends a fake alert with the chosen severities and tier

The bottom line shows what the daemon is doing (image, stage, elapsed time, images left) or that it isn't running.
The TUI talks to the daemon through `semaphore.sock` in the data volume, so run it in the daemon's container

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
uv run semaphore-tui    # TUI against DATA_DIR
```
