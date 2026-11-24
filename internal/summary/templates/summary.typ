// ScanProof period summary.
//
// Every value comes from data.json. Values are inserted as plain text and
// never evaluated as Typst markup.

#let d = json("data.json")

#import "common.typ": *

#set document(title: "Image Security Summary " + d.summary_id)
#set page(
  paper: "us-letter",
  margin: (top: 14mm, bottom: 18mm, x: 15mm),
  footer: context {
    set text(size: 7pt, fill: muted)
    grid(
      columns: (1fr, auto),
      [#d.summary_id · #d.period_label · generated #d.generated_at],
      [Page #counter(page).display() of #counter(page).final().first()],
    )
  },
)
#set text(font: ("DejaVu Sans",), size: 8.4pt, fill: ink)
#set par(leading: 0.5em, spacing: 0.8em)

#grid(
  columns: (1fr, auto),
  align: (left + bottom, right + bottom),
  {
    text(size: 16pt, weight: "bold", fill: navy, "Image Security Summary")
    linebreak()
    text(size: 8pt, fill: muted, d.period_label)
  },
  text(size: 7.4pt, fill: muted, {
    [Summary ]
    text(weight: "bold", fill: ink, d.summary_id)
    linebreak()
    [Generated #d.generated_at]
    linebreak()
    [ScanProof #d.tool_version]
  }),
)
#v(-1.5mm)
#line(length: 100%, stroke: 1.6pt + navy)

#section("Coverage")
#grid(columns: (1fr,) * 3, column-gutter: 2mm, row-gutter: 2mm, ..d.tiles.map(tile))

#section("Remediation against SLA")
#data-table(
  (20mm, 14mm, 16mm, 14mm, 22mm, 22mm, 1fr, 1fr),
  ("Severity", "SLA days", "Opened", "Fixed", "Fixed in SLA", "Median days", "Open, in SLA", "Open, overdue"),
  d.remediation.map(r => (badge(r.at(0)), ..r.slice(1))),
  aligns: (left, right, right, right, right, right, right, right),
)
#note[A finding is tracked when a fix is available and no exception accepts it. It opens at the first scan that reports it and closes at the first later scan of the same image without it. Its deadline is the first-seen date plus the SLA for its severity.]

#section("Fixed after SLA", note: str(d.fixed_late.len()) + " findings")
#if d.fixed_late.len() == 0 {
  note[Every finding fixed in the period was fixed within its SLA.]
} else {
  data-table(
    (1fr, 30mm, 26mm, 18mm, 20mm, 20mm, 12mm),
    ("Image", "ID", "Package", "Severity", "First seen", "Fixed", "Days"),
    d.fixed_late,
    aligns: (left, left, left, left, left, left, right),
  )
}

#section("Open past SLA at the end of the period", note: str(d.overdue.len()) + " findings")
#if d.overdue.len() == 0 {
  note[No finding was open past its SLA at the end of the period.]
} else {
  data-table(
    (1fr, 30mm, 26mm, 18mm, 20mm, 20mm, 12mm),
    ("Image", "ID", "Package", "Severity", "First seen", "Due", "Days"),
    d.overdue,
    aligns: (left, left, left, left, left, left, right),
  )
}

#section("Exceptions")
#kv-table((
  (label: "Applied in the period", value: d.exceptions_applied, mono: false),
  (label: "Expired in the period", value: d.exceptions_expired, mono: false),
))

#section("Population", note: str(d.population.len() + d.population_omitted) + " scans")
#note[The complete list of scans is in population.csv, one row per scan with a link to its evidence. Auditors can sample from it directly.]
#data-table(
  (38mm, 42mm, 16mm, 1fr, 14mm),
  ("Report", "Scanned (UTC)", "Trigger", "Image", "Result"),
  d.population,
)
#if d.population_omitted > 0 {
  note[#d.population_omitted more scans are listed in population.csv.]
}

#section("Evidence")
#kv-table(d.evidence)

#section("SOC 2 reference")
#data-table(
  (18mm, 1fr),
  ("Criteria", "What this summary shows"),
  (
    ("CC7.1", "Images were scanned for known vulnerabilities throughout the period, and findings were tracked against remediation deadlines."),
    ("CC8.1", "Build-time scans checked each change before deployment; their results are in the population."),
    ("CC4.1", "This summary is the periodic check that the scanning control operated for the whole period."),
  ),
)
#note[The mapping is for reference. The service auditor decides whether evidence is sufficient.]
