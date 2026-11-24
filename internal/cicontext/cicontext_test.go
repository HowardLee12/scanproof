package cicontext

import "testing"

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestGitHubPushContext(t *testing.T) {
	c := FromEnv(env(map[string]string{
		"GITHUB_ACTIONS":     "true",
		"GITHUB_SERVER_URL":  "https://github.com",
		"GITHUB_REPOSITORY":  "example-org/example-api",
		"GITHUB_SHA":         "3e1f9a2c7b4d5e6f8a9b0c1d2e3f4a5b6c7d8e9f",
		"GITHUB_REF":         "refs/heads/main",
		"GITHUB_REF_NAME":    "main",
		"GITHUB_RUN_ID":      "12873456211",
		"GITHUB_RUN_ATTEMPT": "2",
		"GITHUB_ACTOR":       "octocat",
		"GITHUB_EVENT_NAME":  "push",
		"GITHUB_WORKFLOW":    "Deploy",
	}))
	if c.Provider != "GitHub Actions" || c.Repository != "example-org/example-api" || c.Branch != "main" {
		t.Errorf("unexpected context %+v", c)
	}
	if c.RunURL != "https://github.com/example-org/example-api/actions/runs/12873456211/attempts/2" {
		t.Errorf("run URL = %q", c.RunURL)
	}
	if c.CommitURL != "https://github.com/example-org/example-api/commit/3e1f9a2c7b4d5e6f8a9b0c1d2e3f4a5b6c7d8e9f" {
		t.Errorf("commit URL = %q", c.CommitURL)
	}
	if c.PullRequest != 0 || !c.InCI() {
		t.Errorf("push builds have no pull request: %+v", c)
	}
}

func TestGitHubPullRequestContext(t *testing.T) {
	c := FromEnv(env(map[string]string{
		"GITHUB_ACTIONS":     "true",
		"GITHUB_SERVER_URL":  "https://github.com",
		"GITHUB_REPOSITORY":  "example-org/example-api",
		"GITHUB_REF":         "refs/pull/482/merge",
		"GITHUB_HEAD_REF":    "feature/login",
		"GITHUB_RUN_ID":      "1",
		"GITHUB_RUN_ATTEMPT": "1",
	}))
	if c.PullRequest != 482 || c.Branch != "feature/login" {
		t.Errorf("unexpected pull request context %+v", c)
	}
	if c.RunURL != "https://github.com/example-org/example-api/actions/runs/1" {
		t.Errorf("first attempts link to the run itself, got %q", c.RunURL)
	}
	if c.PullRequestURL != "https://github.com/example-org/example-api/pull/482" {
		t.Errorf("pull request URL = %q", c.PullRequestURL)
	}
}

func TestOutsideCI(t *testing.T) {
	c := FromEnv(env(nil))
	if c.InCI() || c.Provider != "" {
		t.Fatalf("expected an empty context, got %+v", c)
	}
}

func TestStepSummaryPath(t *testing.T) {
	c := FromEnv(env(map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_STEP_SUMMARY": "/tmp/summary.md"}))
	if c.StepSummaryPath != "/tmp/summary.md" {
		t.Fatalf("got %q", c.StepSummaryPath)
	}
}
