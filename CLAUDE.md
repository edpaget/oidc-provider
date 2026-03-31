# oidc-provider

Full OIDC identity provider implementation.
- **Namespaces**: `oidc-provider.core`, `oidc-provider.authorization`, `oidc-provider.token-endpoint`, `oidc-provider.discovery`, `oidc-provider.protocol`, `oidc-provider.token`, `oidc-provider.store`
- **Features**: Authorization code flow, refresh tokens, client credentials, pluggable storage

---

# General Guidelines

Be concise, straightforward, and avoid hyperbole.

# Clojure Style Guidelines

## Conditionals
- Use `if` for single condition checks, not `cond`
- Only use `cond` for multiple condition branches
- Prefer `if-let` and `when-let` for binding and testing a value in one step
- Consider `when` for conditionals with single result and no else branch
- consider `cond->`, and `cond->>`

## Variable Binding
- Minimize code points by avoiding unnecessary `let` bindings
- Only use `let` when a value is used multiple times or when clarity demands it
- Inline values used only once rather than binding them to variables
- Use threading macros (`->`, `->>`) to eliminate intermediate bindings

## Parameters & Destructuring
- Use destructuring in function parameters when accessing multiple keys
- Example: `[{:keys [::zloc ::match-form] :as ctx}]` for namespaced keys instead of separate `let` bindings
- Example: `[{:keys [zloc match-form] :as ctx}]` for regular keywords

## Control Flow
- Track actual values instead of boolean flags where possible
- Use early returns with `when` rather than deeply nested conditionals
- Return `nil` for "not found" conditions rather than objects with boolean flags

## Comments
- Do not include comments in generated code, unless specifically asked to.
- Section-divider comments (e.g., `;; ---` banners) are acceptable for organizing long namespaces.

## Docstrings

All docstrings should follow the Clojure community style guide and be written in a narrative form with markdown formatting. They should render well with [cljdoc](https://cljdoc.org/) using `[[namespace/symbol]]` syntax for automatic linking.

### Namespace Docstrings
- Every namespace must have a docstring
- Start with a one-line summary (what the namespace provides)
- Follow with extended description for complex modules
- Include usage examples with code blocks when appropriate
- Use `[[namespace/symbol]]` links to reference related namespaces, functions, or protocols
- Organize with markdown headers (`##`, `###`) for major sections

### Function Docstrings
- All public functions must have docstrings
- Private functions should have docstrings when sufficiently complex
- Write in narrative form, describing what the function does and how to use it
- Avoid structured sections like `Args:`, `Returns:`, `Throws:`, or `Raises:`
- Instead, write flowing prose that naturally describes parameters, return values, and behavior
- Use markdown formatting for emphasis, code snippets, and lists
- Use `[[namespace/symbol]]` to link to related functions, protocols, or types
- Include examples when they aid understanding
- For multi-arity functions, describe the different use cases naturally in the narrative

### Protocol and Multimethod Docstrings
- Protocols and multimethods must have docstrings
- Protocol methods should have individual docstrings
- Write in narrative form, describing the contract and expected behavior
- Avoid structured sections; describe parameters and return values naturally

### Macro Docstrings
- Macros must have docstrings
- Write in narrative form describing what the macro does
- Include examples showing usage
- Describe the generated code naturally within the narrative
- Avoid structured sections

### Schema and Data Structure Docstrings
- Malli schemas and important `def` forms should have docstrings
- Describe what the schema validates or what the data represents

## Handler Input Maps
- All handler functions that accept parsed request parameters (query params, form params, JSON body) must expect **keyword keys** (e.g., `:grant_type`, `:redirect_uris`, `:client_id`)
- Ring middleware (`wrap-keyword-params`) or JSON parsing (`json/parse-string body true`) should convert string keys to keywords at the boundary
- Internal option/config maps use kebab-case keywords (e.g., `:client-id`, `:redirect-uris`)

## Malli
- All public functions should use malli schemas.

## Nesting
- Minimize nesting levels by using proper control flow constructs
- Use threading macros (`->`, `->>`) for sequential operations

## Function Design
- Functions should generally do one thing
- Pure functions preferred over functions with side effects
- Return useful values that can be used by callers
- smaller functions make edits faster and reduce the number of tokens
- reducing tokens makes me happy

## Library Preferences
- Prefer `clojure.string` functions over Java interop for string operations
  - Use `str/ends-with?` instead of `.endsWith`
  - Use `str/starts-with?` instead of `.startsWith`
  - Use `str/includes?` instead of `.contains`
  - Use `str/blank?` instead of checking `.isEmpty` or `.trim`
- Follow Clojure naming conventions (predicates end with `?`)
- Favor built-in Clojure functions that are more expressive and idiomatic

## REPL best pratices
- Always reload namespaces with `:reload` flag: `(require '[namespace] :reload)`
- Always change into namespaces that you are working on

## Testing Best Practices
- Use Test Driven Development: write tests first, verify they fail, then write the implementation to make them pass
- Always reload namespaces before running tests with `:reload` flag: `(require '[namespace] :reload)`
- Test both normal execution paths and error conditions
- use small deftest forms that have 5 or fewer assertions.
- Assert on real values — use `(is (= expected actual))` over existence checks like `some?`, `not-empty`, or type predicates like `string?`, `vector?`, `pos?`. When values are nondeterministic (e.g., random tokens), verify them by round-tripping through a store or validator rather than checking their type
- Each `deftest` should generally contain a single `testing` block — split separate scenarios into their own `deftest` forms
- No blank lines inside `deftest` forms
- No inline `;;` comments inside `deftest` forms unless the intent cannot be expressed in the `testing` message or `is` assertion message
- avoid using with-redefs

## Using Shell Commands
- Prefer the idiomatic `clojure.java.shell/sh` for executing shell commands
- Always handle potential errors from shell command execution
- Use explicit working directory for relative paths: `(shell/sh "cmd" :dir "/path")`
- For testing builds and tasks, run `clojure -X:test` instead of running tests piecemeal

## Formatting and Linting

### Formatting
```bash
# Format project
clojure -M:format
```

### Linting
Lint warnings must be treated as errors. The lint must complete with 0 warnings and 0 errors.

```bash
clj-kondo --lint src test
```

## Git Commits
- Use [Conventional Commits](https://www.conventionalcommits.org/) for all commit messages
- Format: `<type>(<scope>): <description>`
- Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `build`, `ci`, `chore`
- Scope is optional but encouraged (e.g., `feat(token): add PKCE support`)
- Keep the subject line under 72 characters
- Use the body for additional context when needed

## Changelog
- **Every `feat` or `fix` commit must have a corresponding `CHANGELOG.md` entry** — treat a missing entry as a build failure
- Follow [Keep a Changelog](https://keepachangelog.com/) format
- Add entries under `## [Unreleased]` in the appropriate section: `Added`, `Fixed`, `Changed`, `Deprecated`, `Removed`, `Security`
- Write entries as concise, human-readable descriptions of what changed (not commit messages)
- Include the relevant RFC or spec section when applicable (e.g., "per RFC 6749 §5.2")
- `refactor` commits that change public API surface or user-visible behavior also require an entry
- Do not update the changelog for internal-only changes like `test`, `docs`, `ci`, `style`, or `chore`
- When completing a task, review `git log` since the last release tag and verify every `feat`/`fix` commit has a changelog entry before considering the work done

## Context Maintenance
- Use `clojure_eval` with `:reload` to ensure you're working with the latest code
- always switch into `(in-ns ...)` the namespace that you are working on
- Keep function and namespace references fully qualified when crossing namespace boundaries

# rdm

rdm is a CLI for managing project roadmaps, phases, and tasks. Use these instructions to interact with plan data exclusively through the rdm CLI.

## Setup

The plan repo location is set via `RDM_ROOT` environment variable or `--root` flag. The project is specified with `--project oidc-provider` (or set `RDM_PROJECT` env var, or configure `default_project` in `rdm.toml`).

## Discovering work

```bash
rdm roadmap list --project oidc-provider       # list all roadmaps with progress
rdm task list --project oidc-provider           # list open/in-progress tasks
rdm task list --project oidc-provider --status all  # list all tasks including done
```

## Reading details

```bash
rdm roadmap show <slug> --project oidc-provider          # show roadmap with phases and body
rdm phase list --roadmap <slug> --project oidc-provider  # list phases with numbers and statuses
rdm phase show <stem-or-number> --roadmap <slug> --project oidc-provider  # show phase details
rdm task show <slug> --project oidc-provider             # show task details
```

Add `--no-body` to any `show` command to suppress body content when you only need metadata.

## Updating status

Always pass `--no-edit` to prevent the CLI from opening an interactive editor.

```bash
rdm phase update <stem-or-number> --status done --no-edit --roadmap <slug> --project oidc-provider
rdm task update <slug> --status done --no-edit --project oidc-provider
```

## Creating items

Always pass `--no-edit` to suppress the interactive editor.

```bash
rdm roadmap create <slug> --title "Title" --body "Summary." --no-edit --project oidc-provider
rdm phase create <slug> --title "Title" --number <n> --body "Details." --no-edit --roadmap <slug> --project oidc-provider
rdm task create <slug> --title "Title" --body "Description." --no-edit --project oidc-provider
```

## Body content

Use `--body` for short inline content. For multiline content, pipe via stdin:

```bash
rdm task create <slug> --title "Title" --no-edit --project oidc-provider <<'EOF'
Multi-line body content goes here.

It supports full Markdown.
EOF
```

Do **not** use `--body` and stdin together — the CLI will error.

## Planning workflow

### Before starting work

Run `rdm roadmap list --project oidc-provider` to see all roadmaps and their progress. Check `rdm task list --project oidc-provider` for open tasks. Identify what is in-progress and what comes next before writing any code.

### Implementing a roadmap phase

1. Read the phase: `rdm phase show <stem-or-number> --roadmap <slug> --project oidc-provider`
2. Plan your approach and get approval before starting
3. Implement the work described in the phase
4. Include a `Done:` line in the git commit message — the post-merge hook will mark the phase done and record the commit SHA.
   **Use the exact roadmap slug and phase stem from the rdm commands above — do NOT invent or paraphrase them:**
   ```
   Done: <roadmap-slug>/<phase-stem>
   ```
5. Check the next phase: `rdm phase list --roadmap <slug> --project oidc-provider`

### Completing a task

1. Implement the work described in the task
2. Include a `Done: task/<slug>` line in the git commit message — the post-merge hook will mark the task done and record the commit SHA.
   **Use the exact task slug from the rdm commands above — do NOT invent or paraphrase it.**

### Discovering bugs or side-work

If you encounter a bug or unrelated improvement while working on a phase, do not fix it inline. Create a task instead:

```bash
rdm task create <slug> --title "Description of the issue" --body "Details." --no-edit --project oidc-provider
```

This keeps the current phase focused and ensures nothing is forgotten.

### When a task grows too complex

If a task becomes large enough to warrant multiple phases, promote it to a roadmap:

```bash
rdm promote <task-slug> --roadmap-slug <new-roadmap-slug> --project oidc-provider
```

## Status transitions

### Phase statuses

- `not-started` → `in-progress` — work begins
- `in-progress` → `done` — work is complete
- `in-progress` → `blocked` — waiting on an external dependency
- `blocked` → `in-progress` — blocker resolved
- `done` is terminal (can be manually reverted if needed)

### Task statuses

- `open` → `in-progress` — work begins
- `in-progress` → `done` — work is complete
- `in-progress` → `wont-fix` — decided not to do
- `open` → `wont-fix` — decided not to do before starting
- `done` and `wont-fix` are terminal
