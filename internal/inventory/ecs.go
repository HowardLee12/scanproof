package inventory

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// describeBatch is the most tasks DescribeTasks accepts per call.
const describeBatch = 100

type ecsAPI interface {
	ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	ListTasks(context.Context, *ecs.ListTasksInput, ...func(*ecs.Options)) (*ecs.ListTasksOutput, error)
	DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
}

// ECS lists the images of running Amazon ECS tasks in one region. It needs
// ecs:ListClusters, ecs:ListTasks and ecs:DescribeTasks.
type ECS struct {
	client   ecsAPI
	Clusters []string // empty means every cluster in the region
}

// NewECS uses the standard AWS configuration chain (AWS_REGION, roles, ...).
func NewECS(ctx context.Context, clusters []string) (ECS, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return ECS{}, fmt.Errorf("load AWS configuration: %w", err)
	}
	return ECS{client: ecs.NewFromConfig(cfg), Clusters: clusters}, nil
}

// List returns the images of every running task.
func (e ECS) List(ctx context.Context) ([]RunningImage, error) {
	clusters := e.Clusters
	if len(clusters) == 0 {
		var err error
		if clusters, err = e.allClusters(ctx); err != nil {
			return nil, err
		}
	}
	out := make([]RunningImage, 0)
	for _, cluster := range clusters {
		images, err := e.clusterImages(ctx, cluster)
		if err != nil {
			return nil, err
		}
		out = append(out, images...)
	}
	return out, nil
}

func (e ECS) allClusters(ctx context.Context) ([]string, error) {
	out := make([]string, 0)
	in := &ecs.ListClustersInput{}
	for {
		page, err := e.client.ListClusters(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("list ECS clusters: %w", err)
		}
		out = append(out, page.ClusterArns...)
		if page.NextToken == nil {
			return out, nil
		}
		in.NextToken = page.NextToken
	}
}

func (e ECS) clusterImages(ctx context.Context, cluster string) ([]RunningImage, error) {
	arns := make([]string, 0)
	in := &ecs.ListTasksInput{Cluster: aws.String(cluster), DesiredStatus: types.DesiredStatusRunning}
	for {
		page, err := e.client.ListTasks(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("list tasks in %s: %w", cluster, err)
		}
		arns = append(arns, page.TaskArns...)
		if page.NextToken == nil {
			break
		}
		in.NextToken = page.NextToken
	}

	name := clusterName(cluster)
	out := make([]RunningImage, 0)
	for start := 0; start < len(arns); start += describeBatch {
		end := min(start+describeBatch, len(arns))
		desc, err := e.client.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: aws.String(cluster), Tasks: arns[start:end]})
		if err != nil {
			return nil, fmt.Errorf("describe tasks in %s: %w", cluster, err)
		}
		for _, task := range desc.Tasks {
			loc := fmt.Sprintf("ecs %s/%s", name, aws.ToString(task.Group))
			for _, c := range task.Containers {
				out = append(out, RunningImage{Reference: aws.ToString(c.Image), Digest: aws.ToString(c.ImageDigest), Locations: []string{loc}})
			}
		}
	}
	return out, nil
}

func clusterName(arnOrName string) string {
	if _, name, ok := strings.Cut(arnOrName, ":cluster/"); ok {
		return name
	}
	return arnOrName
}
