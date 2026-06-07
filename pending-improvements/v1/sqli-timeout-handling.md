# SQLi Tool — Timeout Handling

**Type:** Suggestion

## Description

During testing against `http://testaspnet.vulnweb.com/`, the SQLi tool timed out repeatedly (30s, 60s, 120s) without producing any output or error feedback to the caller.

## Impact

- A single unresponsive tool blocks the full scan pipeline when run sequentially.
- The operator gets no signal about why the tool failed — no error finding, no log message propagated through the MCP response.
- There is no configurable per-tool timeout separate from the HTTP request timeout. If the target is slow or drops certain probe payloads, the tool hangs until the entire MCP request times out.

## Expected Correction

- Introduce a per-tool execution timeout with a sensible default (e.g. 30s) that is independent of the HTTP request timeout.
- When the timeout fires, the tool should return an error finding explaining that the probes did not complete, rather than leaving the caller waiting indefinitely.
- Consider adding a grace period or retry budget so transient network issues do not immediately abort the tool.
