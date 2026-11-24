// Package cicontext reads which change a scan belongs to from the CI
// environment, so a report can be traced back to the commit and pull request.
package cicontext

import (
	"fmt"
	"regexp"
	"strconv"
)

var pullRefPattern = regexp.MustCompile(`^refs/pull/(\d+)/`)

// Context describes the CI run that produced a scan.
type Context struct {
	Provider        string `json:"provider,omitempty"`
	Repository      string `json:"repository,omitempty"`
	Commit          string `json:"commit,omitempty"`
	CommitURL       string `json:"commit_url,omitempty"`
	Branch          string `json:"branch,omitempty"`
	PullRequest     int    `json:"pull_request,omitempty"`
	PullRequestURL  string `json:"pull_request_url,omitempty"`
	Workflow        string `json:"workflow,omitempty"`
	RunURL          string `json:"run_url,omitempty"`
	Actor           string `json:"actor,omitempty"`
	Event           string `json:"event,omitempty"`
	StepSummaryPath string `json:"-"`
}

// InCI reports whether the scan ran in a recognised CI system.
func (c Context) InCI() bool {
	return c.Provider != ""
}

// FromEnv builds the context from environment variables. getenv is usually
// os.Getenv; tests pass a map lookup.
func FromEnv(getenv func(string) string) Context {
	if getenv("GITHUB_ACTIONS") == "true" {
		return fromGitHub(getenv)
	}
	return Context{}
}

func fromGitHub(getenv func(string) string) Context {
	server := getenv("GITHUB_SERVER_URL")
	repo := getenv("GITHUB_REPOSITORY")
	repoURL := ""
	if server != "" && repo != "" {
		repoURL = server + "/" + repo
	}

	c := Context{
		Provider:        "GitHub Actions",
		Repository:      repo,
		Commit:          getenv("GITHUB_SHA"),
		Branch:          getenv("GITHUB_REF_NAME"),
		Workflow:        getenv("GITHUB_WORKFLOW"),
		Actor:           getenv("GITHUB_ACTOR"),
		Event:           getenv("GITHUB_EVENT_NAME"),
		StepSummaryPath: getenv("GITHUB_STEP_SUMMARY"),
	}

	if m := pullRefPattern.FindStringSubmatch(getenv("GITHUB_REF")); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			c.PullRequest = n
		}
		if head := getenv("GITHUB_HEAD_REF"); head != "" {
			c.Branch = head
		}
	}

	if repoURL == "" {
		return c
	}
	if c.Commit != "" {
		c.CommitURL = repoURL + "/commit/" + c.Commit
	}
	if c.PullRequest > 0 {
		c.PullRequestURL = fmt.Sprintf("%s/pull/%d", repoURL, c.PullRequest)
	}
	if runID := getenv("GITHUB_RUN_ID"); runID != "" {
		c.RunURL = repoURL + "/actions/runs/" + runID
		if attempt := getenv("GITHUB_RUN_ATTEMPT"); attempt != "" && attempt != "1" {
			c.RunURL += "/attempts/" + attempt
		}
	}
	return c
}
