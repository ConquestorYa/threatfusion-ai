# Architecture Decision Log

## DEC-001: Multi-source rather than USOM-only

**Decision:** Build a multi-source CTI workflow rather than recreate a single public feed.

**Reason:** USOM is valuable as a data source, but merely recreating USOM would provide little added value. Combining sources with local telemetry supports questions that a public feed alone cannot answer.

## DEC-002: Common `IOCRecord` model

**Decision:** Map provider records into one common internal `IOCRecord` representation.

**Reason:** Different CTI providers must be represented consistently before correlation, matching, and later analysis can be reliable.

## DEC-003: Keep normalization separate from data models

**Decision:** Keep canonicalization functions outside the dataclasses.

**Reason:** Models describe data; normalization transforms external values. This separation keeps the model simple and makes transformations independently testable.

## DEC-004: Preserve original IOC evidence during correlation

**Decision:** Correlation groups equivalent indicators without replacing or deleting the original records.

**Reason:** Source, timing, tags, and other evidence remain important to an analyst. Grouping should organize evidence, not destroy it.

## DEC-005: Threat URLs are data only

**Decision:** Never automatically visit, resolve, open, or follow malicious IOC URLs.

**Reason:** Feed URLs are untrusted indicators. Collectors contact only their official feed endpoints, and returned IOC values are handled as text.

## DEC-006: ML rather than LLM for primary detection

**Decision:** Use machine learning for primary malicious-domain detection; reserve LLM use for optional explanation and reporting.

**Reason:** Detection should be measurable, reproducible, and independently evaluated rather than delegated to a language model whose output is difficult to validate as a detector.

## DEC-007: Start with explainable baseline ML

**Status:** PLANNED.

**Decision:** The planned initial malicious-domain approach is character n-gram TF-IDF with Logistic Regression. Other classical models may be compared later.

**Reason:** This baseline is understandable, reproducible, and suitable for measuring feature and model behavior in a student project.

## DEC-008: Prevent ML data leakage

**Status:** PLANNED.

**Decision:** Future model evaluation should use time-based train/test splitting and source-aware evaluation where appropriate.

**Reason:** Threat intelligence and DNS observations are time-dependent, and careless splitting can let information from the future or from the same source leak into evaluation data.

## DEC-009: Secrets never stored in source control

**Decision:** API keys and other secrets must be supplied through environment variables or equivalent runtime configuration. Secret files are protected by `.gitignore`.

**Reason:** Credentials must not be embedded in source code, documentation, tests, or commits.

## DEC-010: Incremental development

**Decision:** Work in small feature increments: implementation, focused tests, Ruff, review, and Git commit.

**Reason:** Small changes make behavior easier to verify and keep the educational codebase understandable.

## DEC-011: Keep architecture simple

**Decision:** Avoid unnecessary frameworks, cloud services, and database complexity during the three-week student-project scope.

**Reason:** The project should prioritize understandable, reproducible core data and detection workflows over infrastructure that does not yet support a demonstrated requirement.

## DEC-012: SQLite for initial local persistence

**Status:** PLANNED.

**Decision:** Use SQLite as the initial local persistence layer when storage is implemented.

**Reason:** SQLite is lightweight, reproducible, and appropriate for a local educational prototype before any need for a larger database service is demonstrated.