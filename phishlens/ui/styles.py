"""
Design system: colour tokens and the small amount of CSS PhishLens uses.

Colour is reserved for meaning:
  neutral (slate)  - normal information, low / insufficient results
  amber            - warnings (moderate)
  red              - serious risks (high / critical)

This CSS is a static string written by us. It is the ONLY HTML that the
app injects with `unsafe_allow_html=True`; email content never goes
through that path.
"""

TOKENS = {
    "ink": "#0f172a",
    "muted": "#64748b",
    "border": "#e2e8f0",
    "surface": "#f8fafc",
    "accent": "#1d4ed8",
    "amber_fg": "#92400e",
    "amber_bg": "#fffbeb",
    "amber_border": "#fcd34d",
    "red_fg": "#991b1b",
    "red_bg": "#fef2f2",
    "red_border": "#fca5a5",
    "critical_fg": "#ffffff",
    "critical_bg": "#991b1b",
}

CSS = f"""
<style>
  .block-container {{ max-width: 1080px; padding-top: 2rem; }}
  h1, h2, h3 {{ letter-spacing: -0.01em; }}
  .pl-brand {{ font-size: 1.35rem; font-weight: 700; color: {TOKENS['ink']}; margin-bottom: 0; }}
  .pl-tagline {{ color: {TOKENS['muted']}; font-size: 0.9rem; margin-top: 0.1rem; }}

  .pl-banner {{ border: 1px solid {TOKENS['border']}; border-left-width: 6px; border-radius: 10px;
               padding: 1rem 1.25rem; margin: 0.5rem 0 1rem; background: {TOKENS['surface']}; }}
  .pl-banner .lvl {{ font-size: 1.3rem; font-weight: 700; margin: 0; }}
  .pl-banner .desc {{ margin: 0.35rem 0 0; color: {TOKENS['ink']}; }}
  .pl-banner .conf {{ margin: 0.35rem 0 0; color: {TOKENS['muted']}; font-size: 0.9rem; }}
  .pl-banner.neutral {{ border-left-color: {TOKENS['muted']}; }}
  .pl-banner.amber {{ border-left-color: {TOKENS['amber_border']}; background: {TOKENS['amber_bg']}; }}
  .pl-banner.amber .lvl {{ color: {TOKENS['amber_fg']}; }}
  .pl-banner.red {{ border-left-color: {TOKENS['red_border']}; background: {TOKENS['red_bg']}; }}
  .pl-banner.red .lvl {{ color: {TOKENS['red_fg']}; }}
  .pl-banner.critical {{ border-left-color: {TOKENS['critical_bg']}; background: {TOKENS['red_bg']}; }}
  .pl-banner.critical .lvl {{ color: {TOKENS['critical_bg']}; }}

  .pl-pill {{ display: inline-block; font-size: 0.72rem; font-weight: 600; padding: 0.1rem 0.5rem;
             border-radius: 999px; border: 1px solid {TOKENS['border']}; margin-right: 0.35rem;
             color: {TOKENS['muted']}; background: #ffffff; white-space: nowrap; }}
  .pl-pill.amber {{ color: {TOKENS['amber_fg']}; background: {TOKENS['amber_bg']}; border-color: {TOKENS['amber_border']}; }}
  .pl-pill.red {{ color: {TOKENS['red_fg']}; background: {TOKENS['red_bg']}; border-color: {TOKENS['red_border']}; }}
  .pl-pill.critical {{ color: {TOKENS['critical_fg']}; background: {TOKENS['critical_bg']}; border-color: {TOKENS['critical_bg']}; }}

  .pl-label {{ color: {TOKENS['muted']}; font-size: 0.78rem; text-transform: uppercase;
              letter-spacing: 0.04em; margin: 0.4rem 0 0.1rem; }}
  .pl-privacy {{ font-size: 0.8rem; color: {TOKENS['muted']}; border-top: 1px solid {TOKENS['border']};
                padding-top: 0.75rem; margin-top: 1rem; }}
</style>
"""
