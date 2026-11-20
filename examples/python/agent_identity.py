"""Sub-agents for any agent framework (Gemini/ADK, OpenAI Agents SDK, LangGraph, CrewAI, custom).

Standard library only. Two ways for a parent agent to run a sub-agent through the gateway:

1. Its own identity (recommended) - RFC 8693 token exchange:
       sub = exchange_for_sub_agent(AS, parent_token, "researcher", ["read"], ttl_seconds=600)
       # the user approves "researcher" once in the console (blocks up to 2 min the first time)
       mcp = GatewayClient(GW, sub["access_token"])
       mcp.call("files__read_text_file", {"path": "..."})
   Re-exchange whenever the 5-minute token expires; no new approval while the delegation lasts.

2. Tag calls on the parent's own connection - MCP _meta:
       mcp = GatewayClient(GW, parent_token)
       mcp.call("bank__list_accounts", {}, sub_agent="analyst")

With an MCP SDK instead of this helper, pass the sub-agent token as a header, for example:
   Google ADK:          MCPToolset(connection_params=StreamableHTTPConnectionParams(url=GW + "/mcp", headers={"Authorization": "Bearer " + tok}))
   OpenAI Agents SDK:   MCPServerStreamableHttp(params={"url": GW + "/mcp", "headers": {"Authorization": "Bearer " + tok}})
   LangChain adapters:  MultiServerMCPClient({"gw": {"url": GW + "/mcp", "transport": "streamable_http", "headers": {"Authorization": "Bearer " + tok}}})
"""
import json
import urllib.error
import urllib.parse
import urllib.request

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
SUB_AGENT_META = "io.agentidentity/sub_agent"


def exchange_for_sub_agent(auth_server, parent_token, name, actions, ttl_seconds=600, sub_agent_type=None, client_id=None):
    """Trade the parent's access token for a sub-agent token. Raises on denial."""
    form = {
        "grant_type": TOKEN_EXCHANGE,
        "subject_token": parent_token,
        "subject_token_type": ACCESS_TOKEN,
        "sub_agent": name,
        "scope": " ".join(actions),
        "requested_ttl": str(ttl_seconds),
    }
    if sub_agent_type:
        form["sub_agent_type"] = sub_agent_type
    if client_id:
        form["client_id"] = client_id
    req = urllib.request.Request(
        auth_server.rstrip("/") + "/oauth/token",
        data=urllib.parse.urlencode(form).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=150) as r:  # first time waits for the human
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise PermissionError(json.load(e).get("error_description", str(e))) from None


class GatewayClient:
    """Minimal MCP Streamable HTTP client for the Agent Identity gateway."""

    def __init__(self, gateway, token, endpoint="/mcp"):
        self.url, self.token, self.session, self.n = gateway.rstrip("/") + endpoint, token, None, 0
        self._rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "agent-identity-py", "version": "0.1"}})

    def _rpc(self, method, params):
        self.n += 1
        headers = {"Authorization": "Bearer " + self.token, "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        body = json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}).encode()
        with urllib.request.urlopen(urllib.request.Request(self.url, data=body, headers=headers), timeout=150) as r:
            if method == "initialize":
                self.session = r.headers.get("Mcp-Session-Id")
            msg = json.load(r)
        if "error" in msg:
            raise RuntimeError(msg["error"].get("message"))
        return msg["result"]

    def tools(self):
        return [t["name"] for t in self._rpc("tools/list", {})["tools"]]

    def call(self, tool, arguments, sub_agent=None, sub_agent_type=None):
        """Call a tool. Pass sub_agent to attribute the call to a named sub-agent (MCP _meta)."""
        params = {"name": tool, "arguments": arguments}
        if sub_agent:
            params["_meta"] = {SUB_AGENT_META: {"name": sub_agent, "type": sub_agent_type or sub_agent}}
        res = self._rpc("tools/call", params)
        text = "".join(c.get("text", "") for c in res.get("content", []))
        if res.get("isError"):
            raise PermissionError(text)
        return text
