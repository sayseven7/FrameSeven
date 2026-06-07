# Use Targeted Rate Limit Testing

## Problem

Framework v1 sends sequential requests to the target root and reports missing rate limiting when it does not receive HTTP 429 or 503.

Rate limiting is commonly applied only to sensitive operations such as login, password recovery, account creation, or expensive API endpoints.

## Impact

The current result can incorrectly report a vulnerability when the tested endpoint is not expected to be rate limited.

## Expected Correction

Allow the operator to select a relevant endpoint and request pattern. Treat a generic root-page test as informational or inconclusive unless the scan has enough evidence to make a stronger claim.
