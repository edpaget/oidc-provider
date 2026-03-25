---
name: rdm-roadmap
description: Create an rdm roadmap with phases for a topic
allowed-tools:
  - Read
  - Bash
  - Glob
  - Grep
---

Create an rdm roadmap with phases for the topic described in `$ARGUMENTS`.

## Steps

1. **Explore the codebase** to understand the current state relevant to `$ARGUMENTS`. Read key files, search for related code, and build context.
2. **Design phases** that break the work into independently deliverable increments. Each phase should produce a working, testable result.
3. **Create the roadmap**: `rdm roadmap create <slug> --title "Title" --body "Summary." --no-edit --project oidc-provider`
4. **Create each phase** with context, steps, and acceptance criteria in the body:
   ```bash
   rdm phase create <slug> --title "Phase title" --number <n> --no-edit --roadmap <roadmap-slug> --project oidc-provider <<'EOF'
   ## Context
   Why this phase exists and what it builds on.

   ## Steps
   1. First step
   2. Second step

   ## Acceptance Criteria
   - [ ] Criterion one
   - [ ] Criterion two
   EOF
   ```
5. **Verify** the roadmap looks correct: `rdm roadmap show <slug> --project oidc-provider`

## Guidelines

- Aim for 2–6 phases per roadmap
- Each phase should be independently deliverable and testable
- Include Context, Steps, and Acceptance Criteria in every phase body
- Order phases so each builds on the previous one
- Use clear, descriptive slugs (e.g., `add-caching`, `migrate-auth`)
