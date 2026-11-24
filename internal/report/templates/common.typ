// Shared palette and helpers for ScanProof PDF reports.
// Imported by every report template; set rules stay in each template.

#let ink = rgb("#17212b")
#let muted = rgb("#5b6876")
#let rule-color = rgb("#d5dce4")
#let soft = rgb("#f3f6f9")
#let navy = rgb("#123a5a")
#let green = rgb("#137a3f")
#let amber = rgb("#9a5a08")
#let red = rgb("#b42318")
#let mono = "DejaVu Sans Mono"

#let verdict-styles = (
  PASS: (fg: green, bg: rgb("#e3f4ea")),
  WARN: (fg: amber, bg: rgb("#fdf1dc")),
  FAIL: (fg: red, bg: rgb("#fde8e6")),
)
#let severity-colors = (
  CRITICAL: rgb("#8f1d14"),
  HIGH: rgb("#d0451b"),
  MEDIUM: rgb("#c98a07"),
  LOW: rgb("#6b7785"),
)
#let status-colors = (
  violation: red,
  accepted: green,
  fixable: amber,
  nofix: muted,
)


// sticky keeps a section title on the same page as the content after it.
#let section(title, note: none) = block(sticky: true, above: 5mm, below: 1.2mm, {
  block(below: 1.6mm, {
    text(size: 10.5pt, weight: "bold", fill: navy, title)
    if note != none {
      text(size: 8pt, fill: muted, "  ·  " + note)
    }
  })
  line(length: 100%, stroke: 0.6pt + rule-color)
})

#let header-cell(h) = text(size: 6.6pt, weight: "bold", fill: muted, tracking: 0.04em, upper(h))

#let data-table(columns, headers, rows, aligns: auto) = table(
  columns: columns,
  align: aligns,
  stroke: (x, y) => (bottom: 0.5pt + rule-color),
  fill: (x, y) => if y == 0 { soft },
  inset: (x: 1.6mm, y: 1.2mm),
  table.header(..headers.map(header-cell)),
  ..rows.flatten(),
)

#let kv-table(rows) = table(
  columns: (34mm, 1fr),
  stroke: (x, y) => (bottom: 0.5pt + rule-color),
  inset: (x: 1.6mm, y: 1.1mm),
  ..rows
    .map(r => (
      text(fill: muted, r.label),
      if r.mono { text(font: mono, size: 7.4pt, r.value) } else { r.value },
    ))
    .flatten(),
)

#let note(body) = text(size: 7.4pt, fill: muted, body)

#let badge(severity) = box(
  fill: severity-colors.at(severity, default: muted),
  inset: (x: 1.3mm, y: 0.7mm),
  radius: 0.8mm,
  text(size: 6.2pt, weight: "bold", fill: white, severity),
)

#let tile(t) = block(
  width: 100%,
  inset: 2.2mm,
  stroke: (top: 2.2pt + rgb(t.accent), rest: 0.6pt + rule-color),
  {
    text(size: 6.4pt, fill: muted, tracking: 0.05em, upper(t.label))
    linebreak()
    text(size: 14pt, weight: "bold", t.value)
    linebreak()
    text(size: 6.4pt, fill: muted, t.hint)
  },
)

#let pass-fail(passed) = if passed {
  text(weight: "bold", fill: green, "Pass")
} else {
  text(weight: "bold", fill: red, "Violation")
}
