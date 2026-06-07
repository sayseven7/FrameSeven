# Reduce HTTP 200 False Positives

## Problem

Some framework v1 checks treat an HTTP 200 response as sufficient evidence of exposure. Administrative paths can return login pages or soft 404 pages with HTTP 200, and public files such as `robots.txt` are not inherently sensitive.

## Impact

Reports can contain high- or medium-severity findings without evidence that protected data or functionality was exposed.

## Expected Correction

Compare candidate responses with random control paths, detect login and soft 404 responses, and require content-specific evidence before reporting an exposure. Classify intentionally public files according to their actual contents rather than their path alone.
