# Embedded AppSec library

`src/appsec_triage_mcp/core/` contains the local AppSec-Triage-agent runtime snapshot:
137 Python modules, three built-in symbol lists and 84 configuration/prompt assets.
This is an independent copy, not an import, symlink, submodule or build context from
the original checkout. The original checkout is left intact.

`vendor-manifest.json` lists each original relative path, bundled relative path and
original SHA-256. The original MIT license is included in
`LICENSE` at the repository root and in the built wheel's license metadata.

Integration changes to the embedded sources:

- `core/config.py` resolves resources from `core/assets/` inside the installed MCP package.
- `core/prompts/registry.py` composes the base, matching CWE templates, shared
  fragments and finding kind for MCP. Each client selects its own context.
- `default/base.md`, `default/sca.md` and `context/common.md` scope deployment
  assumptions to evidence for the selected project and distinguish collection from verdict writing.
- `core/context/stack.py` checks manifest paths before reading framework markers.

All other source modules and assets were copied unchanged. Legacy orchestration and
provider modules remain available as library source for future tool integration;
the MCP entrypoint does not run an agent or instantiate an LLM provider. There is no
separate `appsec-triage` dependency or executable in this distribution.

The MCP surface exposes scanner and code primitives, bundled instructions and policies,
report generation, Git lifecycle and delivery. New provider calls must not be added to
these tools: analysis is performed by the connected client's model.

Scanner binaries and language servers are installed by the standalone multi-stage
Dockerfile using the tool versions from the source snapshot. Building uses only this
repository and public upstream dependencies; no existing agent image is required.
