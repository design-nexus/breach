# Breach functional audit — 2026-10-13

Breach is a Metasploit Framework RPC frontend with independent Pro-style workflows. It does not connect to commercial Metasploit Pro or currently implement complete Pro feature parity.

## Fixed in this audit

- Unicode console truncation no longer slices inside UTF-8 characters.
- Empty console replies now clear the busy indicator.
- Session interaction subscribes to reads immediately and polls delayed shell/Meterpreter output; successful stop removes its subscription.
- Payload generation sends `LHOST=value` and `LPORT=value`, captures subprocess output, and marks the matching task complete/failed, including spawn failures. The form requires an output file so payload bytes cannot be discarded or printed into the terminal.
- Demo actions update the newest task, rather than an unrelated older row.
- A nonempty `NEXUS_MSF_RPC_PASS` overrides the configured password.
- HTTP failures include request context; IPv6 hosts produce valid bracketed URLs.
- Login uses the configured transport and username without silent TLS-to-plaintext fallback. Locally spawned RPC daemons honor SSL settings and use the matching loopback address.
- Workspace database queries paginate beyond Framework's default 100 records.
- SMB reuse uses `SMBUser`, `SMBPass`, and `SMBDomain`, matching the installed scanner. Reuse skips closed services; credential realm parsing supports `realm_value`.
- Report directories sanitize workspace names and avoid same-second collisions. HTML titles escape workspace content.

## Verification

- Normal suite: 33 unit tests and 3 integration tests pass; manual visual preview and installed-Framework tests are ignored by default.
- Explicit read-only integration passes against installed Metasploit Framework 6.5.6-dev: isolated configuration, temporary loopback daemon, login, console create/read/destroy, snapshot, auxiliary module listing, and module metadata/options retrieval.
- Mock HTTP transport verifies delayed session replies, idle console replies, authentication placement, and multi-page database records. Mock subprocesses verify payload exit/error reporting. No payload, exploit, credential login, or scan against a target was executed.
- Responsive render tests cover 120×40, 100×30, 80×24, 60×20, and minimum sizes, including empty/offline states, focus, dialogs, and footer styles.

- Release binary installed to `~/.local/bin/breach` and verified byte-for-byte against the build. Installed PTY checks pass at 120×40, 100×30, 80×24, and 60×20: action palette, resizing, exit, termios restoration, and alternate-screen restoration.

## Pro-style functionality completion

The gaps identified above have now been implemented: ordered chains, failure policies, fresh snapshots, matching flags, requested report formats, supported module checks with saved results, live Framework catalogs, tracked task completion/cancellation, compatible sequential evidence macros, and complete structured reports with broader redaction. See [Pro-style workflows](pro-workflows.md) for behavior and remaining live-validation limits.

Current normal suite: 58 unit tests plus 3 integration tests pass (61 total). The explicit installed-Framework read-only integration also passes, including full catalog lookup. Commercial Pro APIs/exclusive features remain outside the Framework frontend.

Shared navigation and additional UI checks: [navigation](navigation.md).
