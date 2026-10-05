# Investigation workspace

The primary user is an analyst tracing a finding back to its observations.

Palette: harbor slate `#23394b` navigation, cloud `#f3f6f8` workspace, white `#ffffff` evidence surfaces, ink `#203443`, signal blue `#245bc1`, alert rose `#ae4150`.

Typography: Segoe UI with system fallbacks for the operational interface; Cascadia Code / DejaVu Sans Mono only for recorded command text. Hierarchy comes from spacing and weight. No remotely hosted font dependencies.

Layout: persistent navigation, dataset selector, compact factual counters, and an incident queue adjacent to its evidence timeline. Left aligned observations support scanning and comparison.

```
navigation | dataset and actions
           | dataset counters
           | activity
           | incident queue | findings and source events
```

Review: a marketing hero and decorative attack graph would obscure the analyst's task. The timeline is the visual focus; surrounding surfaces are quiet. Severity colors communicate rule priority, not an invented risk probability. Mobile stacks queue and evidence. The source selector keeps demo and imported observations explicit.
