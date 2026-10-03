"""邮件 MCP Server。

提供 send_email 工具。
外部 sink：发送出去就出边界。
"""

from app.mcp_servers.base import BaseMCPServer, ToolSpec


_SENT: list[dict] = []


def _send_email(args: dict) -> dict:
    to = str(args.get("to", "")).strip()
    subject = str(args.get("subject", "")).strip()
    body = str(args.get("body", ""))

    if not to or "@" not in to:
        return {"error": "invalid_recipient", "to": to}

    record = {"to": to, "subject": subject, "body_len": len(body), "status": "sent"}
    _SENT.append(record)
    return record


def _sent_count() -> int:
    return len(_SENT)


class EmailServer(BaseMCPServer):
    server_id = "email-server"
    fingerprint = "sha256:email-server-v1"

    def _register(self) -> None:
        self.add_tool(
            ToolSpec(
                name="send_email",
                description="Send email to a recipient",
                input_schema={"to": "str", "subject": "str", "body": "str"},
                capability="write:email:external",
                output_labels=["EXTERNAL"],
                risk_level="medium",
                handler=_send_email,
            )
        )