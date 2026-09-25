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

The dashboard accepts two non-secret environment variables:

```text
THREATFUSION_DB_PATH=/app/runtime/threatfusion.sqlite
THREATFUSION_MODEL_DIR=/app/runtime/models/development-001
```

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

The generated SQLite database contains only the CTI cache and refresh metadata.
Local analysis-history tables, including `analyst_feedback` labels/notes
and `analyst_suppressions` policy, DNS uploads, and ML dataset snapshots are
not copied. The trusted model artifact is validated before it is copied.

If the output directory already contains files, rebuild explicitly with:

```text
python scripts/prepare_deployment_bundle.py --overwrite
```

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
