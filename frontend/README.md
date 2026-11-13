# ArgusLoom threat modeling console

The console turns the live ArgusLoom infrastructure graph into an attack-surface overview, contextual node analysis, interpreted blast radius, and explainable attack paths. It is built with React 18, TypeScript, Vite, Tailwind CSS, Radix UI, Cytoscape.js, and `react-cytoscapejs`.

## Run locally

Start the backend from the repository root, then start the frontend:

```bash
cd frontend
npm install
npm run dev
```

The API defaults to `http://localhost:8000`. Set `VITE_API_BASE_URL` before starting Vite to use a different API origin. The application consumes `/graph`, `/health`, `/nodes/{id}/blast-radius`, `/attack-paths`, `/rag/query`, and `/cti/enrich`.

## Cenários de demonstração

Com o backend em modo de desenvolvimento, escolha A, B ou C nos botões
“Cenário” do cabeçalho para ativar o respetivo grafo sem atualizar a página.
Também pode usar a CLI a partir da raiz do repositório:

```bash
argusloom scenario A
argusloom scenario list
```

Os endpoints de seleção em `/dev/scenarios` estão desativados em produção
(`ARGUS_DEV_MODE=false`). Nessa configuração, o seletor é substituído pelo
rótulo “Cenário controlado por CLI”; a CLI continua disponível.

## Screen-to-project-goal mapping

| Screen | Project goals | How it answers the threat-modeling questions |
|---|---|---|
| 1. Attack surface overview | G1, G2, G5 | Shows node/CVE/exposure/CVSS/risk KPIs, the five most exposed assets with STRIDE and risk, the five highest-scoring CVEs and affected assets, the three most represented MITRE ATT&CK/ATLAS techniques, and a decorative graph map. This is the first-screen answer to Q1. |
| 2. Graph Explorer — graph mode | G1, G3, G4 | Displays the filterable infrastructure graph, relationship legend, risk encoding, and contextual node selection. The sidebar filters node kind, STRIDE category, and severity. |
| 2. Graph Explorer — list mode | G1, G2, G5 | Provides a keyboard-operable table of graph nodes with IDs, kind, criticality, exposure, CVE count, STRIDE categories, and selection actions. |
| 3. Selected-node detail | G2, G5 | Explains why the node is risky using its exposure, criticality, CVEs, CVSS, relationship counts, STRIDE categories, and local model score. CVE, ATT&CK, and ATLAS context appears as cards; relationship confidence is identified as link confidence, not enrichment confidence. |
| 4. Blast Radius | G3, G5 | After one action from node detail, summarizes the affected-node count, critical assets, aggregate weighted score, decay rule, and affected nodes ordered by depth with local risk and STRIDE context. The graph highlights the root and affected depth levels. |
| 5. Attack Paths | G4 | A Radix Dialog collects source, target, strategy, and top-k for Yen. Dijkstra returns exactly the single best path and ignores top-k; Yen returns up to K structurally distinct paths ordered by cost. Results show numbered node/relation steps, score interpretation, data-based rationale, and the MITRE chain. The graph highlights the path and labels its steps. |
| 6. Command Palette | G1, G3, G4 | `Ctrl+K` / `Cmd+K` opens a searchable Radix Dialog for node selection, Blast Radius, Attack Paths, and graph refresh. Selecting a node opens its detail and centers it in the graph. |

### Screen descriptions

- **Attack surface overview:** compact KPI strip and three ranked tables beside a non-interactive graph minimap. The tables are the accessible path to the same summary.
- **Graph Explorer:** three-panel filter, graph/list, and node-detail workspace. List mode works with keyboard navigation and a row's “Selecionar” button.
- **Node detail:** rationale, STRIDE badges with explanatory tooltips, incident-edge confidence, and contextual threat-intelligence cards. Unavailable fixture metadata is explicitly identified rather than invented.
- **Blast Radius:** interpreted summary and depth-ordered affected-node list; the graph uses red for the root and orange shades for affected depth.
- **Attack Paths:** source/destination dialog followed by numbered steps, relationship confidence where available, strategy-aware score explanation, and linked ATT&CK/ATLAS technique IDs.
- **Command Palette:** keyboard shortcut opens a focused node/action search dialog; Escape closes it and Radix restores focus.

## WCAG 2.2 AA implementation checklist

| Criterion | Technique used |
|---|---|
| 1.3.1 / 1.3.2 — Info and relationships / meaningful sequence | Semantic landmarks and headings, labeled sections, fieldsets and legends, definition lists, ordered result lists, and tables with captions and scoped headers. |
| 1.4.1 — Use of color | Risk badges combine a shape/icon, color, and a visible text label. Graph colors have a text legend; exposure is also indicated by dashed node borders. |
| 1.4.3 / 1.4.11 — Contrast | Dark design tokens and bordered controls distinguish text and UI boundaries; risk text uses readable foreground colors. Validate the rendered screens with axe and contrast tooling. |
| 2.1.1 / 2.1.2 — Keyboard | Filters, Radix tabs/selects/dialogs, command search, actions, and the HTML node table are keyboard-operable. The graph is not the only selection method; use “Lista” to select nodes. |
| 2.4.7 / 2.4.11 — Focus visible / not obscured | Global `:focus-visible` styling uses a 3px gold outline with offset. The header is not sticky, so it cannot cover focused controls. |
| 2.5.8 — Target size | Buttons and icon controls have minimum dimensions above 24×24 CSS pixels; primary actions are at least 44px tall. |
| 3.3.2 — Labels or instructions | Search, filters, source/destination selects, strategy, and path-count controls have visible or programmatic labels and constraints. |
| 4.1.2 / 4.1.3 — Name, role, value / status messages | Radix supplies dialog/select semantics; controls expose selected/pressed/disabled states. The status bar and asynchronous result regions announce updates. |
| Reduced motion | `prefers-reduced-motion` disables CSS transitions and Cytoscape path pulses/centering animations; highlighted paths remain static with numbered node and edge labels. |
| Dialog behavior | Radix Dialog provides focus trapping, Escape handling, and focus restoration for attack-path and command dialogs. |
| Graph alternative | The overview minimap is `aria-hidden` and non-interactive. The Explorer’s captioned HTML list/table is the keyboard-accessible graph alternative. |

The available Radix packages do not include a Command primitive. To avoid an unapproved dependency, the command palette is a searchable node/action list inside Radix Dialog, preserving the dialog's focus management and keyboard behavior.

## Accessibility verification

With the backend and Vite server running, run the axe CLI:

```bash
npx --yes @axe-core/cli http://127.0.0.1:5173
```

The CLI requires Chrome and a matching ChromeDriver; pass `--chrome-path` and `--chromedriver-path` if automatic detection does not work. Resolve every reported violation before release. Also test the principal flow using only the keyboard: open the palette with `Ctrl+K`, select a node, switch to **Lista**, activate its selection button, request Blast Radius, and calculate an attack path.
