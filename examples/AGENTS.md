# JEV Reflex guidance for coding agents

Before executing potentially destructive, security-sensitive, dependency-changing, persistence-changing, or externally impactful actions, call `jev-reflex check --json` or use `jev-reflex exec -- ...`.

Treat JEV Reflex as an auxiliary probabilistic judge wrapped in deterministic policy. JEV signals are not ground truth and do not make the agent deterministic. In `enforce` mode, do not bypass a `HOLD`; in `review` mode, investigate the reason and request human approval when required. Continue to apply normal planning, permission, testing, and sandboxing practices. Explain any `REVIEW` or `HOLD` result to the user and do not bypass it by changing the evaluated text.
