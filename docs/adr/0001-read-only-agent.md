# Agent only watches — it does not take actions

The Pipeline Monitoring Agent never calls `pause` or `activate` on any flow, no matter what. It finds problems, classifies them, explains them, and suggests what to do. But it is always the operator who decides and acts.

We chose this because we do not yet know how often the detection will be wrong. If the agent pauses a flow that was actually fine, the impact is real and immediate. Starting in watch-only mode lets us tune the thresholds and suppression settings without any risk. Automatic actions can come in a later version, after we have enough data to trust the detection.

**Considered Options**: an autonomous mode (agent acts on "low risk" failures on its own) and a supervised mode (operator approves before the agent acts). We dropped both for v1 for the same reason: the LLM can be wrong, and no blocklist can cover every important flow the operator has not thought to protect yet.
