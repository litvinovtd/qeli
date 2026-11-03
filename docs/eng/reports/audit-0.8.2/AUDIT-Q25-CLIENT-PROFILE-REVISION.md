# Q25-F164: panel client INI revisions

1 October 2026. Base: 0e7fc747. D08 remains **IN_PROGRESS**.

The Client editor loaded profile text without a revision. Two tabs could save the same file in turn, with the last one erasing the first one's changes. Importing a qeli:// link or creating a profile under an existing name also replaced the file without warning. Unbounded read_to_string accepted an arbitrarily large file, while the raw INI path trimmed whitespace and the final newline.

GET now returns a stable snapshot bounded by the shared 256 KiB client-parser limit and a revision of the exact INI bytes. Form and raw INI saves supply expected_revision; creation without a token is allowed only for a free name. Save and import share an in-process mutex and sidecar lock, then read under that lock. Save verifies the revision, while import requires the name to be absent even if an API caller provides a token. A second read before atomic publication detects a manual edit during validation. Read failures and conflicts stop the write. Raw INI retains whitespace and its final newline; automatic dev assignment may still extend the file.

On isolated lab .11, formatting, six client API tests and strict Clippy passed for normal and client-only builds. Log: clientrevision3.log in C:/Users/litvi/OneDrive/Documents/qeli/audit-debt-20260925/server-nat44-egress-phase. Locally, node --check, browser GET-to-POST revision flow and git diff --check passed. The live service on .10 was unchanged.

D08 still covers the other INI/import/URI/QR/store/reconnect adapters and concurrent changes. An external editor ignoring the advisory lock can theoretically write between the last comparison and rename; D07 records that boundary.
