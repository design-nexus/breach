# Breach Pro-style workflows

Breach implements these workflows on Metasploit Framework RPC. The commercial Rapid7 Pro API, exclusive modules, phishing campaigns, and VPN features remain outside this application.

## Discovery and review

Connect on Dash, select Quick pentest in Wizards, edit targets/ports, and confirm with Ctrl-G. Breach waits for `db_nmap` to finish in a dedicated console, refreshes the workspace, loads Framework metadata, and builds a review plan. Discovery does not automatically execute that plan.

The catalog includes the connected Framework's exploit and auxiliary modules. Local installed metadata accelerates lookup; uncached modules use `module.info` through RPC, with eight concurrent metadata requests. Cached metadata is scoped to endpoint/version and refreshed after 24 hours. The live module list is fetched each time; missing metadata is an error rather than a demo fallback. Rank, platform, CVE, and open-service matching constrain the plan. CVE references match exactly after normalization.

Space toggles selection; +/- changes the rank threshold; a rebuilds. The selected row stays visible in large lists and narrow terminals. Ctrl-G confirms execution of selected modules; v (or Ctrl-V / the searchable action) confirms supported checks instead.

Automatic execution supplies per-host RHOSTS/RPORT and the LHOST/LPORT from the Payload wizard. Set those listener values for your environment before running a plan. Required options without defaults cause a visible failure; configure modules individually in the Modules option editor when they require additional inputs. A completed task means the Framework operation finished, not that exploitation succeeded or a session was created.

## Vulnerability validation

The validation wizard imports the selected XML/Nessus file, waits for import and refreshed data, matches vulnerability references, and runs `module.check` on matching modules. It does not invoke `module.execute`. The current minimum-rank threshold applies.

Results include host, module, workspace, check time, Framework check code/message, and structured details. They appear in the validation wizard, Tasks, and reports, and persist in `validations.json`. Unsupported modules are recorded as unsupported; unknown results and errors are not reported as safe targets. Selected review-plan checks can also be run without importing again.

## Ordered chains

Each step finishes before the next begins. Discovery/import changes are reflected in the next plan/report, and newly created sessions are available to later evidence steps. Module operations track UUID/job IDs, poll `module.results`, and acknowledge results.

`on_fail = "stop"` ends the chain at a failed step. `on_fail = "continue"` records the failure and proceeds to the next step; the final status is partial. Invalid policies, ranks, missing macros, empty operations, unsupported report formats, and missing required options fail explicitly.

```toml
name = "validate-and-report"
on_fail = "continue"

[[steps]]
type = "import"
path = "/path/to/scan.xml"

[[steps]]
type = "validate"
min_rank = "good"

[[steps]]
type = "report"
formats = ["html", "json"]
```

Other steps: `discover` (rhosts, ports), `auto_exploit` (min_rank, match_vulns, match_ports), `module` (kind, name, options), and `collect_evidence` (macro). Matching flags are independent; disabling both matches nothing. Auto-exploit steps execute selected high-rank matches after the chain confirmation. Read the full step list in that confirmation; PgUp/PgDn scrolls long dialogs.

New installations seed a validation example using `validate`, not auto-exploit. Existing chain files are preserved; change old validation examples yourself if they contain `auto_exploit`.

## Evidence, credentials, and tasks

A directly invoked evidence macro targets the selected session and verifies its platform. In a chain it runs on compatible workspace sessions. Steps execute sequentially and wait for completion. Missing macros, incompatible sessions, empty macros, and failed post modules produce task failures.

Credential reuse tracks SSH, SMB, FTP, and MySQL scanner jobs. Password credentials use the scanner's appropriate options; SMB supports valid LM:NT hash pairs and domain fields. Unsupported private credential types are skipped instead of being sent as passwords to unrelated scanners. Closed services are skipped. Additional service modules remain available through the normal module editor and chain module steps.

Task statuses are running, complete, partial, failed, cancelled, or demo. Stored running tasks become interrupted on restart, because remote jobs cannot be assumed finished. UUID/job IDs and failure details remain in the task log. Task/validation JSON files are written atomically with mode 0600. Payload generation also participates in task tracking and cancellation; its owned generator is terminated when cancelled.

Ctrl-X (or x in Tasks) confirms cancellation. Breach requests the active Framework job to stop and stops remaining steps. Modules time out after 15 minutes; discovery after 30 minutes. Cancellation closes a private discovery console, but Framework does not expose that console's child Nmap PID; verify remote scanner termination separately if needed. A failed job-stop confirmation is recorded in task details. Shutdown requests cancellation and cleans up owned consoles/daemons.

## Reports

Supported formats are md, html, and json. A chain writes only requested formats; the Reports action writes all three. Reports include full hosts/services/vulnerabilities, sessions, jobs, credentials, loot, notes, audit entries, task history, and validation details. Chain reports refresh workspace data immediately before rendering. Task and validation evidence is scoped to the current workspace.

Redaction masks credential values throughout serialized evidence and fields explicitly named as passwords, tokens, secrets, hashes, or private keys. It cannot recognize every unknown secret embedded in arbitrary text. Unredacted reports retain the evidence. Output directories use mode 0700 and files 0600, sanitize workspace names, avoid collisions, and escape HTML content.

## Verification limits

Automated mocked RPC tests cover ordered execution, fresh imports before matching, validation without execution, unsupported checks, failure policies, timeout/cancellation, private discovery consoles, compatible evidence sessions, formats/redaction, persistence, and large-list navigation. Read-only integration covers the installed Framework's login, console lifecycle, module listing/info/options, and full catalog.

No real target discovery, authentication attempt, exploit, post module, or payload generation was used for validation. Populated live database workflows and remote job cancellation were exercised through mocks, not a live target environment. Those outcomes depend on Framework modules, datastore options, permissions, and target behavior.

Verified normal suite: 61 tests pass. The installed-Framework read-only integration passes separately. Actual Foot screenshots were reviewed: [plan](plan.png), [validation](validation.png), [tasks](tasks.png).

The release is installed at `~/.local/bin/breach`, verified against the build. Installed terminal checks pass at 120×40, 100×30, 80×24, and 60×20, including resizing, palette navigation, exit, and terminal restoration.
