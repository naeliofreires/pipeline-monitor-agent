# Agent only watches — it does not take actions

The automatic Pipeline Monitoring Agent never calls `pause` or `activate` on any flow. It finds problems, classifies them, explains them, and suggests what to do. But it is always the operator who decides and acts.

ADR 0007 adds a narrow exception for supervised, user-initiated Slack flow controls. Those controls are not automatic monitor behavior: they require an authorized operator action and should preferably use a separate control service key.

We chose this because we do not yet know how often the detection will be wrong. If the agent pauses a flow that was actually fine, the impact is real and immediate. Starting in watch-only mode lets us tune the thresholds and suppression settings without any risk. Automatic actions can come in a later version, after we have enough data to trust the detection.

**Considered Options**: an autonomous mode (agent acts on "low risk" failures on its own) and a supervised mode (operator approves before the agent acts). We dropped autonomous actions for v1 for the same reason: the LLM can be wrong, and no blocklist can cover every important flow the operator has not thought to protect yet. Supervised controls were later accepted as the ADR 0007 exception, separate from automatic monitoring.
