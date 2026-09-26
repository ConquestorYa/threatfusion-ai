# Deployment

ThreatFusion AI can be packaged as a Streamlit container for a hosted demo.
The hosted path must keep the same privacy and secret-handling boundaries as
the local application.

## Public mode

Set:

```text
THREATFUSION_PUBLIC_MODE=1
```

Public mode disables:

- browsing shared analysis history
- saving analysis history

This prevents one anonymous visitor from seeing another visitor's persisted
domain findings.

Raw uploaded DNS rows and client IP values remain in memory only.

## Runtime paths

The dashboard accepts non-secret runtime configuration through environment
variables:

```text
THREATFUSION_DB_PATH=/app/runtime/threatfusion.sqlite
THREATFUSION_MODEL_DIR=/app/runtime/models/development-001
THREATFUSION_CTI_STALE_HOURS_THREATFOX=24
THREATFUSION_CTI_STALE_HOURS_URLHAUS=24
THREATFUSION_CTI_STALE_HOURS_SGB=24
```

The three freshness values default to 24 hours and can be tuned independently
to match the maintenance cadence used for each source.

The SQLite database must already contain the CTI cache, and the model directory
must contain the trusted local `model.joblib` and `metadata.json` artifact.

The interactive dashboard does not need ThreatFox or URLhaus API keys. CTI
refresh should be performed as a separate maintenance workflow.

## Container build

```text
docker build -t threatfusion-ai .
```

The image intentionally excludes local `data/`, model artifacts, SQLite
databases, `.env` files, tests, and Git metadata.

## Prepare a sanitized runtime bundle

Do not mount the developer's whole local `data/` tree into a public
container. It can contain dataset snapshots and local analysis history.

For the public portfolio demo, prefer a synthetic CTI cache rather than
redistributing a live copy of third-party feed data:

```powershell
python scripts\generate_public_demo_cti_cache.py
```

This writes only documentation-reserved values such as `.example`,
`203.0.113.0/24`, and `2001:db8::/32` into
`data/demo/public_demo_cti.sqlite`. No ThreatFox, URLhaus, SGB, or other
third-party IOC values are copied. If the file already exists, rebuild it only
with the explicit `--overwrite` flag.

Then create the hosted bundle from that synthetic cache:

```powershell
python scripts\prepare_deployment_bundle.py `
  --source-db data\demo\public_demo_cti.sqlite
```

A private/local deployment can still use the normal live CTI cache. The public
portfolio demo uses synthetic CTI because the repository does not claim broad
redistribution rights for third-party feed contents.

Instead create a minimal hosted-runtime bundle:

```text
python scripts/prepare_deployment_bundle.py
```

The default output is:

```text
data/deployment/runtime/
  threatfusion.sqlite
  models/
    development-001/
      model.joblib
      metadata.json
```

The generated SQLite database contains only the currently active CTI snapshot
and refresh metadata from the selected source database. For the public portfolio
demo, that selected source database should be the synthetic demo cache described
above. Inactive local IOC lifecycle history is intentionally not
copied into the public deployment bundle. Local analysis-history tables,
including `analyst_feedback` labels/notes
and `analyst_suppressions` policy, DNS uploads, and ML dataset snapshots are
not copied. The trusted model artifact is validated before it is copied.

If the output directory already contains files, rebuild explicitly with:

```text
python scripts/prepare_deployment_bundle.py --overwrite
```

## Render public-demo path

For the portfolio-hosted demo, the repository can generate its entire runtime
during the Render build. The generated CTI cache and ML artifact are synthetic
and demo-only; they are not the measured local model or third-party feed data.

Build command:

```text
python -m pip install -r requirements.txt && python -m pip install --no-deps -e . && python scripts/generate_public_demo_runtime.py --output-dir runtime
```

Start command:

```text
streamlit run streamlit_app.py --server.address=0.0.0.0 --server.port=$PORT
```

Environment variables:

```text
THREATFUSION_PUBLIC_MODE=1
THREATFUSION_DB_PATH=runtime/threatfusion.sqlite
THREATFUSION_MODEL_DIR=runtime/models/development-001
```

No ThreatFox or URLhaus credential is required by this public-demo service.
The synthetic demo artifact exists only so visitors can exercise the complete
analysis flow. It must not be cited as measured ML performance. Portfolio ML
metrics come only from the separately frozen/evaluated local artifacts and
aggregate evaluation reports.

## Local public-mode container test

Mount only the sanitized runtime directory:

```text
docker run --rm -p 8501:8501 \
  -e THREATFUSION_PUBLIC_MODE=1 \
  -e THREATFUSION_DB_PATH=/app/runtime/threatfusion.sqlite \
  -e THREATFUSION_MODEL_DIR=/app/runtime/models/development-001 \
  -v ./data/deployment/runtime:/app/runtime:ro \
  threatfusion-ai
```

On Windows PowerShell, use a resolved absolute path if Docker does not accept
the relative volume path. The runtime volume can be mounted read-only because
public mode does not save shared analysis history.

The container runs as a non-root user and exposes Streamlit on port 8501.

## CI container smoke test

GitHub Actions builds the Docker image, starts it in public mode without private
model/CTI assets, and waits for Streamlit's local health endpoint. This catches
container build/start regressions while keeping ignored runtime data and secrets
out of CI.

## Health check

The image health check uses Streamlit's local health endpoint:

```text
/_stcore/health
```

This confirms that the Streamlit process is responding. It does not prove that
the CTI database or model artifact is available; the dashboard reports those
separately in the System status sidebar.

## Secret handling

Do not bake API keys into the image. The public interactive app does not require
feed credentials. If a hosting environment also runs CTI refresh jobs, provide
those credentials only to the maintenance job through the platform's secret
manager.

## Scheduled CTI refresh

The interactive Streamlit request path must not refresh external feeds. Run
`scripts/refresh_cti_cache.py` as a separate maintenance job that has write
access to the runtime SQLite database and receives feed credentials from the
hosting platform's secret manager.

The refresh job and the public web app should use the same
`THREATFUSION_DB_PATH`, but the public web container can keep the runtime
volume read-only. The maintenance job is the only process that needs write
access to the CTI cache.

A simple local/hosted maintenance command is:

```text
python scripts/refresh_cti_cache.py
```

Provide `THREATFOX_AUTH_KEY` and `URLHAUS_AUTH_KEY` only in that maintenance
job's environment. Do not put the values in the repository, Docker image,
command-line arguments, or Streamlit configuration.

Schedule the job comfortably inside the configured source freshness windows.
The default dashboard stale thresholds are 24 hours, so a twice-daily refresh
is a reasonable demo cadence when the hosting platform supports scheduled
jobs. A failed or unexpectedly empty source refresh is rejected by the cache
safety checks instead of replacing healthy data with an empty snapshot.

For Windows local demos, Task Scheduler can invoke the Python command from the
project virtual environment. For Linux/container hosting, use the platform's
scheduled-job facility or cron/systemd timer. Keep credentials in the
platform/service environment rather than a checked-in script.

## Hosted-demo hardening boundary

Before exposing the demo publicly, keep these controls outside the application
at the hosting/reverse-proxy layer:

- HTTPS only
- per-IP request/rate limiting
- request/body limits consistent with the app's 10 MB upload cap
- public mode enabled with shared history disabled
- read-only runtime mount for the web process
- no ThreatFox/URLhaus feed credentials in the web process
- only a separate maintenance job may update the CTI cache
- logs must not record uploaded DNS file contents or client-IP telemetry
- use the sanitized deployment bundle rather than the developer `data/` tree

The repository deliberately does not implement a custom authentication,
rate-limiter, job scheduler, or reverse proxy for v1. Those are hosting-layer
responsibilities and adding them to the Streamlit code would unnecessarily
expand the project scope.

## Production notes

A public demo should also provide:

- HTTPS at the reverse proxy or hosting platform
- request/rate limits at the hosting layer
- bounded upload sizes
- restricted filesystem permissions
- periodic CTI refresh outside the user request path
- monitoring and log retention that does not record uploaded DNS content

ThreatFusion AI remains an educational/portfolio security prototype and should
not be presented as a production SIEM, EDR, or guaranteed malware detector.


## Optional final-evaluation report

The public dashboard can display an aggregate frozen-holdout report through:

```text
THREATFUSION_EVALUATION_REPORT=/runtime/evaluation/final_holdout.json
```

The report is optional. Before the final holdout is collected, the Model
evaluation tab shows a clear development-status message.

To include a completed aggregate report in the sanitized runtime bundle:

```powershell
python scripts\prepare_deployment_bundle.py \
  --evaluation-report data\evaluation\final_holdout.json
```

The report contains aggregate metrics and source-level recall only; it does not
contain holdout domain rows.
