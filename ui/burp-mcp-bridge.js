/**
 * Burp Suite MCP Bridge
 * Connects Claude Code to Burp Suite Pro REST API
 *
 * Prerequisites:
 *   1. Burp Suite Pro installed with REST API enabled (User options → REST API)
 *   2. API key set in ~/.claude/settings.json env.BURP_API_KEY
 *   3. Burp running at http://127.0.0.1:1337
 *
 * The official Burp MCP extension from PortSwigger is recommended over this bridge:
 *   → Burp Suite → Extensions → BApp Store → search "MCP"
 *   Repo: https://github.com/PortSwigger/mcp-server-burpsuite
 *
 * This file is a placeholder — replace with the official extension or the
 * community bridge after installing Burp Suite Pro.
 */

const BURP_API_KEY = process.env.BURP_API_KEY || '';
const BURP_URL     = process.env.BURP_URL     || 'http://127.0.0.1:1337';

if (!BURP_API_KEY || BURP_API_KEY === 'REPLACE_WITH_YOUR_BURP_API_KEY') {
  console.error('[burp-mcp-bridge] No BURP_API_KEY set. Configure in ~/.claude/settings.json');
  process.exit(1);
}

// Placeholder MCP server — replace with official PortSwigger extension
console.log(`[burp-mcp-bridge] Connecting to Burp Suite at ${BURP_URL}`);
console.log('[burp-mcp-bridge] Replace this file with the official PortSwigger MCP extension');
process.exit(0);
