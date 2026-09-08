# Wayfinder Operations

Wayfinder enables structured, frontier-based problem solving across complex, ambiguous tasks. In GitHub Issues, the exploration is tracked through a **Map** issue with linked **Child** issues as work items.

---

## 1. The Map

The map is a single overarching issue that maintains global state, decisions made, and unresolved questions (the fog):

- **Label**: `wayfinder:map`
- **Creation**: `gh issue create --title "<Goal Title> [Map]" --label "wayfinder:map" --body "..."`
- **Sections**:
  - `## Notes`: Context and scope.
  - `## Decisions-so-far`: Running log of accepted design choices and links to resolved tickets.
  - `## Fog`: Known unknowns and unexplored territory.
  - `## Tasks`: Task checklist linking child tickets.

---

## 2. Child Tickets

Each concrete question or implementation slice becomes a child ticket linked to the map:

- **Linking**: Where GitHub sub-issues are enabled, attach via sub-issues API (`gh api`). Otherwise, include `Part of #<map-number>` in the body and list the child in the map's task list.
- **Labels**: `wayfinder:<type>` where type is one of:
  - `wayfinder:research` — investigation of specs, source code, or standards.
  - `wayfinder:prototype` — quick spike or throwaway experiment.
  - `wayfinder:grilling` — stress-testing plans and architecture decisions.
  - `wayfinder:task` — concrete coding or refactoring task.

---

## 3. Dependency & Blocking Tracking

- **Native Dependencies**: When available, link blockers via GitHub's issue dependencies endpoint:
  `gh api --method POST repos/<owner>/<repo>/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`
- **Fallback**: Add a `Blocked by: #<blocker1>, #<blocker2>` line at the top of the child issue body.
- **Unblocked Condition**: A ticket is considered unblocked once all its blocking issues are closed.

---

## 4. Frontier Query & Claim Loop

1. **Find Next Frontier**: Scan open children of the map. Filter out issues that have open blockers or already have an assignee. Take the first eligible ticket in map order.
2. **Claim**: Assign to the active worker:
   `gh issue edit <number> --add-assignee @me`
3. **Execute**: Work on the task following the [Definition of Done](definition-of-done.md).
4. **Resolve**:
   - Post findings/answer: `gh issue comment <number> --body "<summary of solution>"`
   - Close child issue: `gh issue close <number>`
   - Update Map: Append key takeaways and link to the child ticket under `## Decisions-so-far` in the map issue.
