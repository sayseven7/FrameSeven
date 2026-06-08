# Parallelize Small Network Probes

## Problem

Framework v1 still runs some small network probe loops sequentially inside a
single scanner tool. The `ports` tool checks each candidate TCP port one at a
time, and the `content` tool checks each common content path one at a time.

## Impact

Targets with closed, filtered, or slow endpoints can make these tools take
longer than necessary even though each probe is independent. This is most
visible when custom payloads add more content paths or when TCP connection
attempts wait for their timeout.

## Expected Correction

Add simple per-tool worker pools with conservative limits for independent
probes in `ports` and `content`. Preserve deterministic output ordering, keep
request attribution clear, and avoid increasing the default scan load unless
the operator explicitly selects a higher concurrency setting.
