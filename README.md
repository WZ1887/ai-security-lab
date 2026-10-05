# MCP-Guard

**Zero-Trust Security Gateway for AI Agent Tool Execution**

> LLM is a proposer. Policy is a decider.
>
> Tool Description / Tool Result / Memory are untrusted data.
>
> We do not just detect Prompt Injection. We block the full attack chain:
> Prompt → Tool → Data → Sink.

Interactive AI customer-service app with a five-gate security gateway between an AI agent and MCP tool servers.

---

## Why

An AI agent that can call tools is a new attack surface:

- A poisoned tool description can hijack the agent.
- A poisoned knowledge-base document can inject instructions.
- A tool result can contain instructions that the agent obeys.
- A combination of **individually legitimate** tools can leak PII.
- A compromised MCP server can impersonate a trusted one.

Most defenses stop at "detect prompt injection". MCP-Guard enforces **policy** at every boundary.

---

## Architecture
