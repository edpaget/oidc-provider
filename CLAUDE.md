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
clojure -X:format :paths '["."]'
```

### Linting
Lint warnings must be treated as errors. The lint must complete with 0 warnings and 0 errors.

```bash
clj-kondo --lint src test
```

## Context Maintenance
- Use `clojure_eval` with `:reload` to ensure you're working with the latest code
- always switch into `(in-ns ...)` the namespace that you are working on
- Keep function and namespace references fully qualified when crossing namespace boundaries
