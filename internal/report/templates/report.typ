// ScanProof image scan report.
//
// Every value comes from data.json, which ScanProof writes next to this file.
// Values are inserted as plain text and never evaluated as Typst markup, so
// package names or file paths in scan results cannot change the document.

#let d = json("data.json")

#import "common.typ": *

#set document(title: "Container Image Scan Report " + d.report_id)
#set page(
  paper: "us-letter",
  margin: (top: 14mm, bottom: 18mm, x: 15mm),
  footer: context {
    set text(size: 7pt, fill: muted)
    grid(
      columns: (1fr, auto),
      [#d.report_id · #d.digest_short · generated #d.generated_at],
      [Page #counter(page).display() of #counter(page).final().first()],
    )
  },
)
#set text(font: ("DejaVu Sans",), size: 8.4pt, fill: ink)
#set par(leading: 0.5em, spacing: 0.8em)

// ---------------------------------------------------------------- page 1

#grid(
  columns: (1fr, auto),
  align: (left + bottom, right + bottom),
  {
    text(size: 16pt, weight: "bold", fill: navy, "Container Image Scan Report")
    linebreak()
    text(size: 8pt, fill: muted, "Vulnerability and secret scan run before deployment")
  },
  text(size: 7.4pt, fill: muted, {
    [Report ]
    text(weight: "bold", fill: ink, d.report_id)
    linebreak()
    [Generated #d.generated_at]
    linebreak()
    [ScanProof #d.tool_version]
  }),
)
#v(-1.5mm)
#line(length: 100%, stroke: 1.6pt + navy)

#let vs = verdict-styles.at(d.verdict)
#block(
  width: 100%,
  fill: soft,
  stroke: 0.6pt + rule-color,
  inset: 3mm,
  grid(
    columns: (30mm, 1fr),
    column-gutter: 4mm,
    align: horizon,
    box(
      width: 100%,
      fill: vs.bg,
      stroke: 1.2pt + vs.fg,
      radius: 1.5mm,
      inset: (y: 2.4mm),
      align(center, text(size: 14pt, weight: "bold", fill: vs.fg, tracking: 0.06em, d.verdict)),
    ),
    {
      text(size: 9.4pt, weight: "bold", d.headline)
      linebreak()
      text(size: 8pt, fill: muted, d.detail)
    },
  ),
)

#section("Image")
#kv-table(d.image_rows)

#section(d.context_title)
#kv-table(d.context_rows)

#section("Findings")
#grid(columns: (1fr,) * d.tiles.len(), column-gutter: 2mm, ..d.tiles.map(tile))

#section("Policy evaluation")
#data-table(
  (1fr, 22mm, 14mm, 18mm),
  ("Rule", "Threshold", "Found", "Status"),
  d.rules.map(r => (r.name, r.threshold, r.found, pass-fail(r.passed))),
  aligns: (left, left, right, left),
)

#section("Scanner")
#data-table(
  (1fr, 30mm, 52mm),
  ("Engine", "Version", "Database updated"),
  d.scanners,
)

// ---------------------------------------------------------------- details

#section("Critical and High vulnerabilities", note: str(d.vulns.len() + d.vulns_omitted) + " findings")
#if d.vulns.len() == 0 {
  note[No Critical or High vulnerabilities were found.]
} else {
  data-table(
    (17mm, 30mm, 1fr, 1fr, 1fr, 9mm, 27mm),
    ("Severity", "ID", "Package", "Installed", "Fixed in", "CVSS", "Status"),
    d.vulns.map(v => (
      badge(v.severity),
      text(font: mono, size: 7.2pt, v.id),
      v.package,
      v.installed,
      v.fixed,
      v.cvss,
      text(weight: "bold", fill: status-colors.at(v.status_kind, default: muted), v.status),
    )),
    aligns: (left, left, left, left, left, right, left),
  )
  if d.vulns_omitted > 0 {
    note[#d.vulns_omitted more Critical and High findings are listed in results.json.]
  }
}

#section("Medium and Low vulnerabilities by package")
#if d.lower_by_package.len() == 0 {
  note[No Medium or Low vulnerabilities were found.]
} else {
  data-table(
    (1fr, 18mm, 18mm, 18mm),
    ("Package", "Medium", "Low", "Fixable"),
    d.lower_by_package,
    aligns: (left, right, right, right),
  )
}

#section("Secrets", note: str(d.secrets.len()) + " found")
#if d.secrets_note != "" {
  note(d.secrets_note)
} else if d.secrets.len() == 0 {
  note[No keys, tokens or passwords were found in image files.]
}
#if d.secrets.len() > 0 {
  data-table((38mm, 1fr, 1fr, 30mm), ("Rule", "Title", "Location", "Status"), d.secrets)
  note[The matched text is never stored or printed.]
}

#section("Approved exceptions", note: str(d.exceptions_applied.len()) + " applied to this image")
#if d.exceptions_applied.len() == 0 {
  note[No exceptions were applied.]
} else {
  data-table((24mm, 34mm, 1fr, 34mm, 18mm), ("ID", "Finding", "Reason", "Approved by", "Expires"), d.exceptions_applied)
}
#if d.exceptions_expired.len() > 0 {
  v(2mm)
  text(weight: "bold", "Expired exceptions that no longer apply")
  data-table((24mm, 34mm, 1fr, 34mm, 18mm), ("ID", "Finding", "Reason", "Approved by", "Expired"), d.exceptions_expired)
}
#if d.exceptions_unused.len() > 0 {
  v(2mm)
  text(weight: "bold", "Active exceptions that matched nothing in this image")
  data-table((24mm, 34mm, 1fr, 34mm, 18mm), ("ID", "Finding", "Reason", "Approved by", "Expires"), d.exceptions_unused)
}
#note[Exceptions are kept in the scanned repository, so the pull request that added each one is its approval record. An expired exception stops applying and the finding counts again.]

#section("Evidence integrity")
#kv-table(d.integrity_rows)

#section("SOC 2 reference")
#data-table(
  (18mm, 62mm, 1fr),
  ("Criteria", "Requirement", "What this report shows"),
  (
    ("CC7.1", "Detect new vulnerabilities and configuration changes that introduce them.", "Known vulnerabilities were identified against a vulnerability database with the update time shown above."),
    ("CC8.1", "Changes are tested and approved before they are implemented.", "The scan ran in the pipeline for the change shown above, and the policy result was recorded before deployment."),
  ),
)
#note[The mapping is for reference. The service auditor decides whether evidence is sufficient.]
