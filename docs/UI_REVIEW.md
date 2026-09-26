# SOC workspace UI review

The interface starts with the analyst's task: upload telemetry, review priority domains, then inspect evidence. The large hero and gradients were replaced with a compact header, slate surfaces, restrained teal navigation, and semantic verdict colors. Technical details stay available in disclosures.

## Changed files

| File | Purpose |
| --- | --- |
| .streamlit/config.toml | Native dark/light theme tokens |
| streamlit_app.py | Sidebar routing, intake state, priority findings and existing analysis orchestration |
| src/threatfusion/ui_theme.py | Escaped components, shared colors, responsive CSS and native-theme chart typography |
| src/threatfusion/ui_components.py | CTI status summaries, empty states, literal domain/verdict/source filters |
| src/threatfusion/ui_charts.py | Existing verdict and relationship figures with semantic colors |
| src/threatfusion/ui_investigation.py | Evidence-first domain details, existing feedback/suppression controls |
| src/threatfusion/ui_history.py | Saved-run browsing and existing review/retention workflow |
| src/threatfusion/ui_evaluation.py | Frozen holdout report and its existing interpretation caveats |
| tests/test_streamlit_feedback.py | Public-mode guards, navigation persistence, four upload dispatches, exports and feedback |
| tests/test_ui_components.py | Filtering, HTML escaping, contrast, chart semantics and loaded evaluation |
| docs/UI_REVIEW.md | This review guide |

Backend parsers, detection, ML, CTI matching/freshness, persistence, report schemas and dependencies are unchanged. Public mode still excludes local history and feedback. Exact known-domain matches remain the only Known Threat evidence scope. Filters affect displayed findings only; exports keep the original aggregate analysis.

## Local verification

From an existing checkout with the configured trusted artifact and CTI database:

~~~powershell
python -m pip install -r requirements.txt
python -m pip install --no-deps -e .
python -m streamlit run streamlit_app.py --server.port 8502
~~~

For an isolated synthetic UI review, use the existing generators in a new folder. This does not measure model performance or fetch real threat intelligence:

~~~powershell
$uiRuntime = Join-Path $env:TEMP ('threatfusion-ui-' + [guid]::NewGuid())
python scripts/generate_public_demo_runtime.py --output-dir $uiRuntime
python scripts/generate_demo_dns_csv.py --db "$uiRuntime/threatfusion.sqlite" --output "$uiRuntime/demo.csv"
$env:THREATFUSION_DB_PATH = "$uiRuntime/threatfusion.sqlite"
$env:THREATFUSION_MODEL_DIR = "$uiRuntime/models/development-001"
$env:THREATFUSION_EVALUATION_REPORT = "$uiRuntime/final_holdout.json"
$env:THREATFUSION_PUBLIC_MODE = '0'
python -m streamlit run streamlit_app.py --server.address 127.0.0.1 --server.port 8502
~~~

Open http://127.0.0.1:8502 and upload demo.csv from that temporary folder. The synthetic runtime has no final holdout report, so the evaluation page should say Pending holdout. Do not interpret synthetic scores as production accuracy.

Review sequence:

1. Inspect CTI source summaries and expand source metadata. Fresh/stale/unknown/not-cached states preserve existing freshness rules.
2. Analyze the CSV. Intake collapses, priority findings come first, and counts distinguish unique domains from DNS events.
3. Search/filter Domain findings; clear the filters. Open Domain investigation, IOC evidence, Related activity and Export & save.
4. Save aggregate history, open Analysis history, then return to Analyze telemetry. Results must persist. Switching input format or explicitly removing the upload clears stale results.
5. Switch Light/Dark in the native app menu without rerunning. Check text, surfaces, verdict colors and graphs. At 390 px, open the sidebar and scroll result tabs/tables.
6. Inspect pending evaluation. A real existing frozen report uses the same loader and thresholds. Automated tests also render a synthetic loaded report, including source diagnostics and n/a values.
7. Restart with THREATFUSION_PUBLIC_MODE=1 to review the history-free public UI.

## Validation recorded

- Full pytest suite: **526 passed** (Windows, pinned requirements).
- Ruff: all checks passed. git diff --check: clean.
- Release audit: tracked tree and local baseline history passed; new UI files scanned separately before publishing.
- Browser: actual synthetic CSV upload and analysis, priority queue, domain evidence, related graph, export controls, save/history/navigation, pending and synthetic loaded evaluation.
- Browser: desktop 1254 x 900; narrow 390 x 844; dark/light transitions. Narrow document width equaled viewport width (390 px).
- Regression coverage: CSV, Zeek, Pi-hole and AdGuard UI dispatch; public-mode no-read/no-write guards; aggregate exports unchanged; literal filters; text/verdict token contrast at least 4.5:1.

The browser runtime and screenshots use reserved documentation domains and synthetic data. The loaded evaluation screenshot is explicitly marked SYNTHETIC UI FIXTURE; its report was moved out of the configured evaluation path after QA. No merge or deployment is part of this change.

## Follow-up screenshot set

For review on your own trusted local data, capture: Analyze telemetry with CTI sidebar and priority queue; an investigated domain with evidence; Analysis history with feedback; Model evaluation with operating points; and a 390 px light-mode view. Redact sensitive information. Screenshots from this implementation run are supplied separately in the task outputs.
