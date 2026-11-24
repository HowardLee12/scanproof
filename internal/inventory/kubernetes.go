package inventory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	pageSize          = "500"
	maxErrorBody      = 300
)

// Kubernetes lists the images of running pods through the Kubernetes API.
// It needs permission to list pods (see docs/rescan.md for the RBAC rules).
type Kubernetes struct {
	BaseURL   string
	Token     string
	Client    *http.Client
	Namespace string // empty means every namespace
}

// InCluster configures access from a pod, using its service account.
func InCluster(namespace string) (Kubernetes, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return Kubernetes{}, errors.New("not running in a Kubernetes pod (KUBERNETES_SERVICE_HOST is not set)")
	}
	token, err := os.ReadFile(serviceAccountDir + "/token")
	if err != nil {
		return Kubernetes{}, fmt.Errorf("read service account token: %w", err)
	}
	ca, err := os.ReadFile(serviceAccountDir + "/ca.crt")
	if err != nil {
		return Kubernetes{}, fmt.Errorf("read cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return Kubernetes{}, errors.New("cluster CA file holds no certificates")
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	return Kubernetes{
		BaseURL:   "https://" + net.JoinHostPort(host, port),
		Token:     strings.TrimSpace(string(token)),
		Client:    client,
		Namespace: namespace,
	}, nil
}

type podList struct {
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []struct {
		Metadata struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"metadata"`
		Spec struct {
			Containers []struct {
				Name  string `json:"name"`
				Image string `json:"image"`
			} `json:"containers"`
		} `json:"spec"`
		Status struct {
			ContainerStatuses []struct {
				Name    string `json:"name"`
				Image   string `json:"image"`
				ImageID string `json:"imageID"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

// List returns the images of every running pod, following result pages.
func (k Kubernetes) List(ctx context.Context) ([]RunningImage, error) {
	path := "/api/v1/pods"
	if k.Namespace != "" {
		path = "/api/v1/namespaces/" + url.PathEscape(k.Namespace) + "/pods"
	}
	out := make([]RunningImage, 0)
	cont := ""
	for {
		q := url.Values{"fieldSelector": {"status.phase=Running"}, "limit": {pageSize}}
		if cont != "" {
			q.Set("continue", cont)
		}
		var page podList
		if err := k.get(ctx, path+"?"+q.Encode(), &page); err != nil {
			return nil, err
		}
		for _, pod := range page.Items {
			loc := fmt.Sprintf("k8s %s/%s", pod.Metadata.Namespace, pod.Metadata.Name)
			specImages := map[string]string{}
			for _, c := range pod.Spec.Containers {
				specImages[c.Name] = c.Image
			}
			for _, cs := range pod.Status.ContainerStatuses {
				ref := imageReference(specImages[cs.Name], cs.Image, cs.ImageID)
				out = append(out, RunningImage{Reference: ref, Digest: registryDigest(cs.ImageID), Locations: []string{loc}})
			}
		}
		if page.Metadata.Continue == "" {
			return out, nil
		}
		cont = page.Metadata.Continue
	}
}

func (k Kubernetes) get(ctx context.Context, pathAndQuery string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.BaseURL+pathAndQuery, nil)
	if err != nil {
		return fmt.Errorf("build Kubernetes request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+k.Token)
	req.Header.Set("Accept", "application/json")
	resp, err := k.Client.Do(req)
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return fmt.Errorf("list pods: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("decode pod list: %w", err)
	}
	return nil
}

// imageReference picks the most trustworthy name for a container's image.
// The pod spec says what was asked for. The status field can hold a bare
// image ID or another tag of the same image, so it is the last resort after
// the repository in imageID.
func imageReference(specImage, statusImage, imageID string) string {
	if specImage != "" {
		return specImage
	}
	id := strings.TrimPrefix(strings.TrimPrefix(imageID, "docker-pullable://"), "docker://")
	if repo, _, ok := strings.Cut(id, "@"); ok && repo != "" {
		return repo
	}
	return statusImage
}

// registryDigest extracts the manifest digest from a container status
// imageID such as "docker-pullable://repo@sha256:...". A bare "sha256:..."
// is a local image ID, not a registry digest, so it is ignored.
func registryDigest(imageID string) string {
	_, digest, ok := strings.Cut(imageID, "@")
	if !ok {
		return ""
	}
	return digest
}
