package inventory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestMergeDeduplicatesByDigest(t *testing.T) {
	got := Merge([]RunningImage{
		{Reference: "repo/api:1", Digest: digestA, Locations: []string{"k8s prod/api-1"}},
		{Reference: "repo/api:latest", Digest: digestA, Locations: []string{"k8s prod/api-2"}},
		{Reference: "repo/web:2", Digest: digestB, Locations: []string{"ecs prod/web"}},
		{Reference: "repo/local:dev", Locations: []string{"file"}},
	})
	if len(got) != 3 {
		t.Fatalf("got %d images: %+v", len(got), got)
	}
	if got[0].Reference != "repo/api:1" || strings.Join(got[0].Locations, ",") != "k8s prod/api-1,k8s prod/api-2" {
		t.Errorf("first = %+v", got[0])
	}
	if got[0].ScanReference() != "repo/api@"+digestA {
		t.Errorf("scan reference = %q", got[0].ScanReference())
	}
	if got[2].ScanReference() != "repo/local:dev" {
		t.Errorf("an image without a digest is scanned by its reference, got %q", got[2].ScanReference())
	}
}

func TestFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "images.txt")
	content := "# GPU hosts\nghcr.io/org/vllm:0.9@" + digestA + "\n\n  repo/web:2  \n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := File{Path: path}.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Digest != digestA || got[0].Reference != "ghcr.io/org/vllm:0.9" || got[1].Reference != "repo/web:2" {
		t.Fatalf("got %+v", got)
	}
	if _, err := (File{Path: filepath.Join(t.TempDir(), "missing")}).List(context.Background()); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestKubernetesListsRunningPods(t *testing.T) {
	pages := []string{
		`{"metadata":{"continue":"page2"},"items":[{"metadata":{"namespace":"gpu","name":"vllm-0"},"status":{"containerStatuses":[
		   {"image":"cr.example/vllm:0.9","imageID":"cr.example/vllm@` + digestA + `"},
		   {"image":"cr.example/sidecar:1","imageID":"docker-pullable://cr.example/sidecar@` + digestB + `"}]}}]}`,
		`{"metadata":{},"items":[{"metadata":{"namespace":"gpu","name":"vllm-1"},"status":{"containerStatuses":[
		   {"image":"cr.example/vllm:0.9","imageID":"cr.example/vllm@` + digestA + `"},
		   {"image":"local/build:dev","imageID":"sha256:cccc"}]}}]}`,
	}
	var auth, path, query []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = append(auth, r.Header.Get("Authorization"))
		path = append(path, r.URL.Path)
		query = append(query, r.URL.RawQuery)
		page := 0
		if r.URL.Query().Get("continue") == "page2" {
			page = 1
		}
		w.Write([]byte(pages[page]))
	}))
	defer srv.Close()

	k := Kubernetes{BaseURL: srv.URL, Token: "t0ken", Client: srv.Client(), Namespace: "gpu"}
	got, err := k.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	merged := Merge(got)
	if len(merged) != 3 {
		t.Fatalf("got %+v", merged)
	}
	vllm := merged[0]
	if vllm.Digest != digestA || len(vllm.Locations) != 2 || vllm.Locations[0] != "k8s gpu/vllm-0" {
		t.Errorf("vllm = %+v", vllm)
	}
	if merged[2].Digest != "" {
		t.Error("a bare config ID is not a registry digest and must not be used")
	}
	if auth[0] != "Bearer t0ken" || path[0] != "/api/v1/namespaces/gpu/pods" || !strings.Contains(query[0], "status.phase%3DRunning") {
		t.Errorf("request: auth %q path %q query %q", auth[0], path[0], query[0])
	}
}

func TestKubernetesAllNamespacesAndErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/pods" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"pods is forbidden"}`))
	}))
	defer srv.Close()
	_, err := Kubernetes{BaseURL: srv.URL, Token: "x", Client: srv.Client()}.List(context.Background())
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected a 403 error, got %v", err)
	}
}

func TestInClusterRequiresServiceAccount(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := InCluster(""); err == nil {
		t.Fatal("expected an error outside a cluster")
	}
}

type fakeECS struct{ calls int }

func (f *fakeECS) ListClusters(_ context.Context, in *ecs.ListClustersInput, _ ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	return &ecs.ListClustersOutput{ClusterArns: []string{"arn:aws:ecs:us-east-2:1:cluster/prod"}}, nil
}

func (f *fakeECS) ListTasks(_ context.Context, in *ecs.ListTasksInput, _ ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	if in.DesiredStatus != types.DesiredStatusRunning {
		return nil, nil
	}
	if in.NextToken == nil {
		return &ecs.ListTasksOutput{TaskArns: []string{"task-1"}, NextToken: aws.String("more")}, nil
	}
	return &ecs.ListTasksOutput{TaskArns: []string{"task-2"}}, nil
}

func (f *fakeECS) DescribeTasks(_ context.Context, in *ecs.DescribeTasksInput, _ ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	f.calls++
	out := &ecs.DescribeTasksOutput{}
	for _, arn := range in.Tasks {
		out.Tasks = append(out.Tasks, types.Task{
			TaskArn: aws.String(arn),
			Group:   aws.String("service:api"),
			Containers: []types.Container{
				{Image: aws.String("1.dkr.ecr.us-east-2.amazonaws.com/api:v3"), ImageDigest: aws.String(digestA)},
			},
		})
	}
	return out, nil
}

func TestECSListsRunningTasks(t *testing.T) {
	fake := &fakeECS{}
	got, err := ECS{client: fake}.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	merged := Merge(got)
	if len(merged) != 1 || merged[0].Digest != digestA || len(merged[0].Locations) != 1 ||
		merged[0].Locations[0] != "ecs prod/service:api" {
		t.Fatalf("got %+v", merged)
	}
}

func TestDescribeJSONShape(t *testing.T) {
	data, _ := json.Marshal(RunningImage{Reference: "a", Digest: digestA, Locations: []string{"x"}})
	if !strings.Contains(string(data), `"locations":["x"]`) {
		t.Fatalf("got %s", data)
	}
}
