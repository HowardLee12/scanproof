package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/HowardLee12/scanproof/internal/policy"
)

// Discord embed colours, matching the PDF verdict colours.
const (
	colorPass = 0x137a3f
	colorWarn = 0xc98a07
	colorFail = 0xb42318
)

// Limits from the Discord and Slack APIs.
const (
	discordTitleMax       = 256
	discordDescriptionMax = 4096
	discordFieldMax       = 1024
	slackHeaderMax        = 150
	slackTextMax          = 3000
)

func verdictColor(v policy.Verdict) int {
	switch v {
	case policy.VerdictPass:
		return colorPass
	case policy.VerdictFail:
		return colorFail
	default:
		return colorWarn
	}
}

// encode writes JSON without HTML escaping, so Slack link syntax such as
// <url|text> reaches the API unchanged.
func encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("encode notification: %w", err)
	}
	return buf.Bytes(), nil
}

func violationText(m Message) string {
	if len(m.Violations) == 0 {
		return ""
	}
	text := "Violations:\n• " + strings.Join(m.Violations, "\n• ")
	if m.MoreViolations > 0 {
		text += fmt.Sprintf("\n…and %d more", m.MoreViolations)
	}
	return text
}

// DiscordPayload builds a Discord webhook body.
func DiscordPayload(m Message) ([]byte, error) {
	description := m.Summary
	if v := violationText(m); v != "" {
		description += "\n\n" + v
	}
	fields := make([]map[string]any, 0, len(m.Fields))
	for _, f := range m.Fields {
		fields = append(fields, map[string]any{
			"name": f.Name, "value": truncate(f.Value, discordFieldMax), "inline": true,
		})
	}
	embed := map[string]any{
		"title":       truncate(m.Title, discordTitleMax),
		"description": truncate(description, discordDescriptionMax),
		"color":       verdictColor(m.Verdict),
		"fields":      fields,
		"footer":      map[string]string{"text": "Report " + m.ReportID},
	}
	if m.URL != "" {
		embed["url"] = m.URL
	}
	return encode(map[string]any{
		"username": "ScanProof",
		// Never let text from scan results (image names, packages) ping anyone.
		"allowed_mentions": map[string]any{"parse": []string{}},
		"embeds":           []any{embed},
	})
}

// slackEscape escapes the three characters Slack treats as control characters.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// SlackPayload builds a Slack incoming-webhook body.
func SlackPayload(m Message) ([]byte, error) {
	body := slackEscape(m.Summary)
	if v := violationText(m); v != "" {
		body += "\n\n" + slackEscape(v)
	}
	fieldBlocks := make([]map[string]string, 0, len(m.Fields))
	for _, f := range m.Fields {
		fieldBlocks = append(fieldBlocks, map[string]string{
			"type": "mrkdwn", "text": fmt.Sprintf("*%s*\n%s", slackEscape(f.Name), slackEscape(f.Value)),
		})
	}
	context := "Report " + slackEscape(m.ReportID)
	if m.URL != "" {
		context += fmt.Sprintf(" · <%s|CI run>", m.URL)
	}
	blocks := []any{
		map[string]any{"type": "header", "text": map[string]string{"type": "plain_text", "text": truncate(m.Title, slackHeaderMax)}},
		map[string]any{"type": "section", "text": map[string]string{"type": "mrkdwn", "text": truncate(body, slackTextMax)}},
	}
	if len(fieldBlocks) > 0 {
		blocks = append(blocks, map[string]any{"type": "section", "fields": fieldBlocks})
	}
	blocks = append(blocks, map[string]any{
		"type": "context", "elements": []map[string]string{{"type": "mrkdwn", "text": context}},
	})
	return encode(map[string]any{
		"text":   slackEscape(m.Title + " · " + m.Summary),
		"blocks": blocks,
	})
}
