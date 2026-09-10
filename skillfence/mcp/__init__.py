"""MCP proxy — puts SkillFence in front of a real MCP server.

To the real MCP client (Claude Code, or any MCP-speaking agent), this
proxy *is* the MCP server. To the real downstream MCP server, this proxy
*is* the client. Every `tools/call` passing through gets authorized by the
same RuntimeGateway/PolicyEngine/RiskEngine/HumanGate pipeline the DVAS
labs already use, before the real request is ever forwarded to the real
server. Everything else (initialize, tools/list, resources/*, prompts/*,
notifications) passes through unmodified — this proxy only ever makes a
security decision, never invents protocol behavior.
"""
