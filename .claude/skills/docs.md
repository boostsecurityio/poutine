Review recent code changes and update all relevant documentation:

1. **Rule documentation** (`docs/content/en/rules/<rule_id>.md`):
   - If a new rule was added, create a new markdown file following the existing format:
     ```
     ---
     title: "Rule Title"
     slug: rule_id
     url: /rules/rule_id/
     rule: rule_id
     severity: error|warning|note
     ---
     ## Description
     ## Remediation
     ## See Also
     ```
   - If an existing rule was modified, update its description, remediation, or examples
   - Reference existing rule docs in `docs/content/en/rules/` for format guidance

2. **README.md** — Update if CLI commands, flags, or usage patterns changed

3. **MCP_INTEGRATION.md** — Update if MCP tools were added, removed, or changed

4. **CONTRIBUTING.md** — Update if development workflow, testing, or build process changed

5. **Structured finding metadata** (`docs/content/en/structured-finding-metadata.md`) — Update if finding JSON fields changed

Read the changed files first to understand what needs documenting, then make the updates.
