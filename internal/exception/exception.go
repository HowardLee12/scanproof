// Package exception loads approved risk acceptances. Each exception names the
// finding it covers, why it was accepted and when it expires. Exceptions live
// in the scanned repository, so the pull request that adds one is the approval
// record.
package exception

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/HowardLee12/scanproof/internal/model"
)

const dateLayout = "2006-01-02"

// Date is a calendar day in UTC.
type Date struct {
	t time.Time
}

// UnmarshalYAML accepts YYYY-MM-DD, quoted or not.
func (d *Date) UnmarshalYAML(node *yaml.Node) error {
	parsed, err := time.Parse(dateLayout, strings.TrimSpace(node.Value))
	if err != nil {
		return fmt.Errorf("line %d: date %q must use the form YYYY-MM-DD", node.Line, node.Value)
	}
	*d = Date{t: parsed}
	return nil
}

// UnmarshalText reads YYYY-MM-DD, so results.json can be decoded again.
func (d *Date) UnmarshalText(text []byte) error {
	parsed, err := time.Parse(dateLayout, strings.TrimSpace(string(text)))
	if err != nil {
		return fmt.Errorf("date %q must use the form YYYY-MM-DD", text)
	}
	*d = Date{t: parsed}
	return nil
}

// MarshalText writes the date as YYYY-MM-DD.
func (d Date) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

func (d Date) String() string {
	if d.t.IsZero() {
		return ""
	}
	return d.t.Format(dateLayout)
}

// IsZero reports whether the date was never set.
func (d Date) IsZero() bool {
	return d.t.IsZero()
}

// Exception accepts one finding until it expires.
type Exception struct {
	ID      string `yaml:"id" json:"id"`
	Finding string `yaml:"finding" json:"finding"`
	Package string `yaml:"package,omitempty" json:"package,omitempty"`
	// Path limits the exception to one file. It is required for secrets, so
	// accepting a test fixture never accepts the same kind of secret elsewhere.
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
	// Artifact limits the exception to some images and directories; without
	// it the exception applies to every artifact it is used with.
	Artifact   Artifacts `yaml:"artifact,omitempty" json:"artifact,omitempty"`
	Reason     string    `yaml:"reason" json:"reason"`
	ApprovedBy string    `yaml:"approved_by,omitempty" json:"approved_by,omitempty"`
	Expires    Date      `yaml:"expires" json:"expires"`
}

type file struct {
	Exceptions []Exception `yaml:"exceptions"`
}

// Source identifies the exceptions file a scan used, so its evidence shows
// exactly which file it was.
type Source struct {
	Path   string
	SHA256 string
}

// Load reads and validates an exceptions file.
func Load(path string) ([]Exception, Source, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, Source{}, fmt.Errorf("read exceptions file %s: %w", path, err)
	}
	list, err := Parse(data)
	if err != nil {
		return nil, Source{}, fmt.Errorf("exceptions file %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return list, Source{Path: path, SHA256: hex.EncodeToString(sum[:])}, nil
}

// Parse decodes and validates exceptions. Unknown keys are rejected so that a
// typo such as "expire:" cannot silently create an exception that never ends.
func Parse(data []byte) ([]Exception, error) {
	if err := checkStructure(data); err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f file
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse exceptions: %w", err)
	}
	if err := validate(f.Exceptions); err != nil {
		return nil, err
	}
	return f.Exceptions, nil
}

func validate(list []Exception) error {
	seen := make(map[string]bool, len(list))
	for i, ex := range list {
		where := fmt.Sprintf("exception %d", i+1)
		if ex.ID != "" {
			where = fmt.Sprintf("exception %s", ex.ID)
		}
		switch {
		case strings.TrimSpace(ex.ID) == "":
			return fmt.Errorf("%s: id is required", where)
		case strings.TrimSpace(ex.Finding) == "":
			return fmt.Errorf("%s: finding is required (a CVE ID, a secret rule ID or a malware signature)", where)
		case strings.TrimSpace(ex.Reason) == "":
			return fmt.Errorf("%s: reason is required", where)
		case ex.Expires.IsZero():
			return fmt.Errorf("%s: expires is required; every exception must end", where)
		case ex.Package != "" && ex.Path != "":
			return fmt.Errorf("%s: use package for a vulnerability or path for a secret, not both", where)
		case seen[ex.ID]:
			return fmt.Errorf("%s: duplicate id", where)
		}
		if err := ex.Artifact.validate(); err != nil {
			return fmt.Errorf("%s: %w", where, err)
		}
		seen[ex.ID] = true
	}
	return nil
}

// Active reports whether the exception still applies at now. It applies
// through the end of its expiry day, in UTC.
func (e Exception) Active(now time.Time) bool {
	endOfDay := e.Expires.t.AddDate(0, 0, 1)
	return now.UTC().Before(endOfDay)
}

// MatchesVulnerability reports whether the exception covers v.
func (e Exception) MatchesVulnerability(v model.Vulnerability) bool {
	if !strings.EqualFold(e.Finding, v.ID) {
		return false
	}
	if e.Path != "" && !samePath(e.Path, v.Target) {
		return false
	}
	return e.Package == "" || strings.EqualFold(e.Package, v.Package)
}

// MatchesSecret reports whether the exception covers s. A secret exception
// must name the file; without a path it never matches.
func (e Exception) MatchesSecret(s model.Secret) bool {
	return e.Path != "" && strings.EqualFold(e.Finding, s.RuleID) && samePath(e.Path, s.Target)
}

// MatchesMalware reports whether the exception covers a malware detection.
// Like secrets, it must name the file.
func (e Exception) MatchesMalware(d model.MalwareDetection) bool {
	return e.Path != "" && strings.EqualFold(e.Finding, d.Signature) && samePath(e.Path, d.Path)
}

func samePath(a, b string) bool {
	return strings.TrimPrefix(a, "/") == strings.TrimPrefix(b, "/")
}
