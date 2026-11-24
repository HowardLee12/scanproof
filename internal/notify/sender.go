package notify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Environment variables that hold webhook URLs.
const (
	EnvDiscordWebhook = "SCANPROOF_DISCORD_WEBHOOK_URL"
	EnvSlackWebhook   = "SCANPROOF_SLACK_WEBHOOK_URL"
)

// maxErrorBody bounds how much of a webhook's error response is reported.
const maxErrorBody = 200

// Target is one configured chat webhook.
type Target struct {
	Name  string
	URL   string
	build func(Message) ([]byte, error)
}

// TargetsFromEnv returns a target for each webhook variable that is set.
func TargetsFromEnv(getenv func(string) string) []Target {
	candidates := []Target{
		{Name: "Discord", URL: getenv(EnvDiscordWebhook), build: DiscordPayload},
		{Name: "Slack", URL: getenv(EnvSlackWebhook), build: SlackPayload},
	}
	out := make([]Target, 0, len(candidates))
	for _, t := range candidates {
		if strings.TrimSpace(t.URL) != "" {
			out = append(out, t)
		}
	}
	return out
}

// Sender posts messages to webhooks.
type Sender struct {
	Client    *http.Client
	UserAgent string
}

// Send posts m to target. Errors never contain the webhook URL.
func (s Sender) Send(ctx context.Context, target Target, m Message) error {
	u, err := url.Parse(strings.TrimSpace(target.URL))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%s webhook URL must be a valid https:// URL", target.Name)
	}
	body, err := target.build(m)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build %s request", target.Name)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.UserAgent != "" {
		// Some webhook hosts reject requests with a default library User-Agent.
		req.Header.Set("User-Agent", s.UserAgent)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return fmt.Errorf("send to %s: %s", target.Name, redact(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return fmt.Errorf("send to %s: HTTP %d %s", target.Name, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

// redact drops the URL that net/http includes in transport errors.
func redact(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return uerr.Err.Error()
	}
	return "request failed"
}
