# Issue Tracker: GitHub

Issues and task specifications for this repository are tracked in GitHub Issues via the `gh` CLI.

---

## Guiding Principles for Using `gh`

1. **Context Awareness**: Run `gh` commands from within the local repository clone; `gh` automatically detects the repository target (`jiraphat-j/AgentSec`) from `git remote -v`.
2. **Prefer Structured & Filtered Queries**: When querying issues programmatically, query only the fields needed (e.g. using `--json` and `--jq` or targeted `--label` filters) to keep agent context clean and focused.
3. **Transparent Audit Trail**: Every significant action (status transition, decision, blocker, or handoff) should be documented as a comment on the ticket.
4. **Wayfinding**: For complex, multi-step explorations and goal breakdowns, refer to [wayfinder.md](wayfinder.md).

---

## Core Operations

### Reading Issues
- Retrieve an issue's description, status, and conversation history using `gh issue view <number> --comments`.
- To inspect specific fields in JSON format, add `--json number,title,body,labels,state`.

### Searching & Listing Issues
- List active work: `gh issue list --state open`.
- Filter by triage status: `gh issue list --label "<triage-label>"`.
- To find issues ready for implementation: `gh issue list --label "ready-for-agent"`.

### Creating Issues
- Create a new ticket with `gh issue create --title "<title>" --body "<body>"`.
- Multi-line descriptions can be supplied via a heredoc or file (`--body-file`).
- When a skill instructs to "publish to the issue tracker", create an issue following this convention.

### Commenting & Updating
- Post updates, test outputs, or findings: `gh issue comment <number> --body "..."`.
- Update metadata or labels: `gh issue edit <number> --add-label "..." --remove-label "..."`.

### Closing Issues
- Once an issue meets the [Definition of Done](definition-of-done.md), close it with an explanatory comment linking the solution:
  `gh issue close <number> --comment "Resolved via <commit/PR>..."`.

---

## Pull Requests as a Request Surface

**PRs as a request surface: no.** *(Set to `yes` if external contributors submit PRs that serve as feature requests; `/triage` checks this flag.)*

When set to `yes`, PRs follow the same triage labels and lifecycle states as issues, using corresponding `gh pr` commands (`gh pr view`, `gh pr list`, `gh pr comment`, `gh pr edit`).
