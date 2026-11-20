# github-forge-v3

A standalone GitHub-compatible git forge in a single Node 22 process
(`main.ts`, standard library only, no dependencies).

It serves:

- **Git smart HTTP** — protocol v2 (`ls-refs`, `fetch`) and v0
  (`upload-pack`, `receive-pack`) with real SHA-1 git objects, packs
  (plain, OFS and REF deltas), shallow fetches and fast-forward push
  validation.
- **REST v3** — repositories, branches, commits, contents, labels,
  issues, comments and pull requests.
- **GraphQL v4** — viewer, repository, issue and pull-request queries,
  cursor pagination, `__type` introspection and mutations.
- **MCP** — Streamable HTTP JSON-RPC 2.0 with `server/discover`,
  `initialize`, `tools/list` and six tools (`create_repo`, `get_repo`,
  `create_issue`, `list_issues`, `create_pull_request`,
  `merge_pull_request`).

Data lives in an in-memory store. Run with:

```sh
MAKEFUN_SHOP_TOKEN=<token> node main.ts
```

The server binds an ephemeral port and, when `MAKEFUN_ENV_URL` is set,
registers it with the trial environment and exits when the trial is
done. Without `MAKEFUN_ENV_URL` it simply serves forever (local use).
