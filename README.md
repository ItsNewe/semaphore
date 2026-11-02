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
| `APPRISE_URLS` | – | See [Apprise URL Reference](https://appriseit.com/getting-started/universal-syntax/) |
| `MIN_SEVERITY` | `High` | Alert threshold: `critical`, `high`, `medium`, `low` |
| `ONLY_FIXED` | `false` | Only alert when an upstream fix exists |
| `RESCAN_INTERVAL_HOURS` | `24` | Re-match SBOMs against a fresh DB |
| `SCAN_ON_PULL` | `false` | Also react to `image pull` events |
| `EXCLUDE_IMAGES` | – | Regex to filter image names |
| `ALERT_MAX_LINES_PER_IMAGE` | `10` | CVE lines listed per image in an alert |
| `ALERT_MAX_CHARS` | `1800` | Body cap |
| `PRUNE_REMOVED_IMAGES` | `true` | Prune SBOMs of deleted images |
| `LOG_LEVEL` | `INFO` | `DEBUG` shows Syft/Grype errors per reference |


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
