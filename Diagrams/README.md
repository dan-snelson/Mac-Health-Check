# Mac Health Check — Documentation Diagrams

## Overview

This directory contains AI-generated visual diagrams supporting the [Mac Health Check documentation](https://snelson.us/mhc). The diagrams use [Mermaid](https://mermaid.js.org) syntax, which renders automatically on GitHub, and cover the complete Mac Health Check ecosystem from admin configuration through runtime execution.

---

## Six Available Diagrams

| File | Title | Description |
|---|---|---|
| [01-system-architecture.md](01-system-architecture.md) | System Architecture | Complete ecosystem from admin configuration through runtime execution |
| [02-script-execution-flow.md](02-script-execution-flow.md) | Script Execution Flow | Decision logic executed on every script invocation |
| [03-health-check-categories.md](03-health-check-categories.md) | Health Check Categories | Visual map of all health checks organized by category |
| [04-deployment-workflow.md](04-deployment-workflow.md) | Deployment Workflow | Step-by-step administrator guide for deploying via MDM |
| [05-operation-modes.md](05-operation-modes.md) | Operation Modes | Behavior comparison across all five operation modes |
| [06-health-check-reference.md](06-health-check-reference.md) | Health Check Reference | Text-only reference for organization defaults and all health checks |

---

## Rendering Options

### GitHub (Recommended)
Mermaid diagrams render automatically when viewing `.md` files on GitHub. No setup required.

### VS Code
1. Install the [Markdown Preview Mermaid Support](https://marketplace.visualstudio.com/items?itemName=bierner.markdown-mermaid) extension
2. Open any `.md` file and press `Cmd+Shift+V` to preview

### Mermaid Live Editor
1. Open [mermaid.live](https://mermaid.live)
2. Copy the contents of any `mermaid` code block
3. Paste into the editor for interactive viewing and PNG/SVG export

---

## Exporting to PNG or SVG

Use the [Mermaid CLI](https://github.com/mermaid-js/mermaid-cli) for high-resolution exports:

```bash
# Install Mermaid CLI
npm install -g @mermaid-js/mermaid-cli

# Export a diagram to PNG (standard, for blog posts / documentation)
mmdc -i 01-system-architecture.md -o 01-system-architecture.png -w 1200

# Export a diagram to PNG (high-resolution, for presentations)
mmdc -i 01-system-architecture.md -o 01-system-architecture.png -w 3840

# Export a diagram to SVG (vector, ideal for documentation sites)
mmdc -i 01-system-architecture.md -o 01-system-architecture.svg
```

---

## Color Palette

All diagrams use a consistent color scheme:

| Color | Hex | Used For |
|---|---|---|
| Light Blue | `#e1f5ff` | Script components, code files |
| Light Green | `#c8e6c9` | Success states, deployment artifacts |
| Light Yellow | `#fff4e6` / `#ffecb3` | Processing steps, decisions |
| Light Red | `#ffcdd2` | Error / critical states |
| Light Purple | `#f3e5f5` | Configuration, preferences |
| Light Grey | `#cfd8dc` | Exit paths, inactive states |
| Light Teal | `#b2dfdb` | Data collection, check execution |

---

## File Naming Convention

Files follow the pattern `[NN]-[descriptive-name].md`:

- `NN` — Two-digit sequence number for logical ordering
- `descriptive-name` — Lowercase, hyphen-separated description

When adding a new diagram, use the next available sequence number and follow the same header structure as existing files (title, overview, Mermaid block, component descriptions).

---

## Resources

- [Mermaid Documentation](https://mermaid.js.org/intro/)
- [Mermaid Live Editor](https://mermaid.live)
- [Mac Health Check Repository](https://github.com/dan-snelson/Mac-Health-Check)
- [Mac Health Check Documentation](https://snelson.us/mhc)
