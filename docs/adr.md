# Architecture Decision Records

## ADR-001: TF-IDF for Drift Detection (not LLM)

**Status**: Accepted

**Context**: We need to detect semantic role drift in Agent conversations — when an Agent's responses gradually deviate from their established behavioral baseline, potentially indicating a prompt injection attack.

**Decision**: Use TF-IDF vectorization with cosine distance, not a large language model.

**Rationale**:
- **Zero GPU dependency**: TF-IDF runs on CPU with minimal memory, suitable for deployment on any server
- **Deterministic**: Same input always produces same output, critical for audit trail integrity
- **Fast**: Sub-millisecond per analysis vs. seconds for LLM inference
- **Lightweight dependency**: scikit-learn is a standard scientific package, no special hardware
- **Sufficient accuracy**: For detecting *drift* (relative change), TF-IDF captures keyword distribution shifts effectively. We don't need semantic understanding — we need to detect when the *pattern* changes
- **Explainable**: Feature importance is directly inspectable, unlike neural embeddings

**Consequences**: May miss subtle semantic shifts that preserve keyword distribution. Mitigated by tracking consecutive deviations (3 strikes rule) and combining with other signals in the reputation system.

---

## ADR-002: In-Memory Session Keys (not Database)

**Status**: Accepted

**Context**: Zero-Trust Context Isolation requires per-session AES-256 encryption keys for sealing Agent context data. Where should these keys be stored?

**Decision**: Store keys in application memory only. Never persist to disk or database.

**Rationale**:
- **Forward security**: When the process terminates, all keys are destroyed. Past sessions cannot be retroactively decrypted even if the server is compromised
- **Attack surface reduction**: No database table of keys to protect. No key rotation logic needed. No risk of key exfiltration via SQL injection
- **Simplicity**: No key management infrastructure (KMS, HSM) required for the core isolation feature
- **Session semantics**: Context isolation is per-session by design. Keys should have the same lifecycle as sessions
- **Compliance**: Aligns with zero-trust principle of minimal persistence

**Consequences**: Keys are lost on server restart, meaning sealed contexts from previous sessions cannot be unsealed. This is acceptable because: (a) sessions are short-lived, (b) the audit log captures all decisions, and (c) new sessions generate new keys.

---

## ADR-003: Behavior Consistency in Reputation Score

**Status**: Accepted

**Context**: The Agent Reputation System needs to detect when an Agent's behavior pattern changes unexpectedly — a strong signal of compromise or prompt injection.

**Decision**: Include a `consistency_bonus` (up to +10) based on KL-divergence of daily resource access distributions vs. 7-day average.

**Rationale**:
- **Statistical rigor**: KL-divergence is the standard measure of distributional shift. It's asymmetric (direction matters) and information-theoretic
- **Early warning**: Gradual behavior changes that don't trigger individual policy violations still shift the distribution. KL-divergence catches these before they become incidents
- **Interpretable**: "Agent X's access pattern today is 3.2x different from its 7-day average" is actionable for security analysts
- **Robust to noise**: Using 7-day rolling average smooths out normal day-to-day variation. Only sustained shifts affect the score
- **Complementary**: Works alongside deny-rate and suspicious-pattern metrics that catch *individual* anomalies. Consistency catches *systemic* drift

**Consequences**: Requires at least 2 days of history before consistency can be computed. New Agents get a neutral bonus (0). The 7-day window is configurable but trades off between responsiveness and stability.
