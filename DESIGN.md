# Design System: Uptime
**Project ID:** local-self-hosted-uptime

## 1. Visual Theme & Atmosphere

Uptime should feel like a **calm operations room** rather than a harsh monitoring console. The product serves serious infrastructure work, but the interface should lower stress instead of amplifying it. The overall mood is **measured, crisp, and trustworthy**: generous spacing, restrained color, and sharp status cues reserved for moments that actually matter.

The visual language balances two ideas:

- **Operational clarity:** health, latency, and incidents must scan quickly.
- **Product polish:** the app should feel intentional enough to trust with production systems.

The experience should read as **signal-first**, with data and actions surfacing early, while decorative details stay soft and atmospheric. Public pages should feel transparent and reassuring. Private admin surfaces should feel focused and instrument-grade.

## 2. Color Palette & Roles

### Core Foundations
- **Cloudwashed Paper** (`#F5F7FB`) – The primary light canvas for public experiences. Keeps the page bright without using stark white.
- **White Signal Card** (`#FFFFFF`) – Primary card and panel background. Used for service cards, settings panels, and modal surfaces.
- **Midnight Control Plane** (`#0B1220`) – Deep operational backdrop for the admin shell and dense console areas.
- **Graphite Frame** (`#1E293B`) – Dark structural color for admin panels, elevated bars, and strong separators.

### Brand & Navigation
- **Tidal Teal** (`#0F766E`) – Primary brand accent. Used for key CTAs, focus rings, and selected states that should feel composed rather than loud.
- **Signal Sky** (`#0EA5E9`) – Secondary accent for links, supporting highlights, and subtle atmospheric gradients.
- **Aurora Mint** (`#D9F99D`) – Soft positive accent reserved for health-forward highlights and gentle status glow treatments.

### Typography & Structure
- **Deep Ink** (`#0F172A`) – Primary text color on light surfaces. Used for headings and high-priority content.
- **Slate Readout** (`#334155`) – Secondary text for body copy, labels, and descriptive content.
- **Fog Annotation** (`#64748B`) – Muted text, helper copy, metadata, and inactive UI.
- **Mist Line** (`#D7DEE8`) – Hairline borders, dividers, card outlines, and low-noise structure.

### Status Semantics
- **Operational Green** (`#16A34A`) – Healthy service state, success feedback, and positive badges.
- **Advisory Amber** (`#D97706`) – Degraded state, maintenance, and cautionary system messaging.
- **Incident Red** (`#DC2626`) – Down state, destructive actions, and failure feedback.

## 3. Typography Rules

**Display / Section Font:** `Space Grotesk`  
Used for page titles, section headers, nav items, and compact labels that benefit from a more architectural voice.

**Primary UI Font:** `IBM Plex Sans`  
Used for body text, forms, tables, descriptions, and action labels. It should feel precise and humane.

**Operational Meta Font:** `IBM Plex Mono`  
Used sparingly for regions, timestamps, build metadata, DNS instructions, and machine-adjacent readouts.

### Hierarchy & Weights
- **Page Titles:** Semi-bold to bold (`600-700`), slightly tight tracking, large but not theatrical.
- **Section Labels:** Semi-bold (`600`), uppercase or compact title case, modest letter-spacing for structure.
- **Body Copy:** Regular (`400`) with comfortable line-height around `1.55-1.65`.
- **Status / Meta Labels:** Medium (`500`) or semi-bold (`600`) with mono accents when machine context matters.

## 4. Component Stylings

### Buttons
- **Shape:** Soft, engineered corners. Think “machined pill-card hybrid” rather than perfectly round or fully square.
- **Primary Actions:** Tidal Teal (`#0F766E`) background with white text and a slightly deeper hover state.
- **Secondary Actions:** White or transparent surfaces with Mist Line (`#D7DEE8`) borders and Deep Ink (`#0F172A`) text.
- **Danger Actions:** Incident Red (`#DC2626`) with white text. These should read as serious but not alarming by default.

### Cards & Panels
- **Corner Style:** Generously rounded (`16-24px`) with clear edge definition.
- **Surface:** White Signal Card (`#FFFFFF`) on public pages and Graphite Frame (`#1E293B`) in the admin interface.
- **Depth:** Soft diffused shadows on light surfaces; flatter elevation in admin, with contrast coming from border and tone instead of large shadows.
- **Border Strategy:** Most surfaces should have a visible but gentle Mist Line border. Dark surfaces should use translucent slate borders.

### Inputs & Forms
- **Inputs on light surfaces:** White fill with Mist Line border and a Tidal Teal focus ring.
- **Inputs on dark surfaces:** Midnight Control Plane fill with slate borders and a brighter teal/sky focus edge.
- **Labels:** Compact, calm, and clear. Avoid oversized labels that compete with the data.

### Tables & Readouts
- Rows should feel breathable and readable, not grid-heavy.
- Use mono accents for machine values such as region names, build info, and CLI snippets.
- Status should be legible through both color and wording.

### Navigation
- Top-level navigation should feel like a **mission strip**: compact, anchored, and always visible.
- Active states should use an accent underline or pill treatment rather than loud background fills.

## 5. Layout Principles

- **Whitespace strategy:** generous outer framing with tighter inner operational density.
- **Content width:** public pages should stay comfortably readable; admin pages can be wider but still centered and structured.
- **Scanning rhythm:** major summaries first, detail disclosures second, long-form operational instructions last.
- **Mobile behavior:** stack vertically, preserve button tap sizes, and let tables scroll rather than collapsing critical data into ambiguity.

## 6. Motion & Interaction

- Hover and focus should feel crisp and fast, generally `160-220ms`.
- Use motion to confirm structure and affordance, not to decorate.
- Cards may lift subtly on hover; modals and badges should not bounce.

## 7. Screen-Specific Guidance

### Public Status Page
- Lead with confidence and transparency.
- Make overall state obvious within one glance.
- Incident and maintenance messaging should be visible, calm, and plainly written.

### Admin Console
- Treat this like an operations cockpit with polished ergonomics.
- Dense data is acceptable as long as the hierarchy is disciplined.
- Management tasks, DNS instructions, and cost data should feel trustworthy and easy to verify.

## 8. Implementation Notes

- Prefer CSS variables so public and admin experiences can share a single semantic vocabulary.
- Reserve strong semantic colors for true state changes; do not spend warning/red tones on decoration.
- When adding new views, ask: “Does this make the operator calmer and faster?”
