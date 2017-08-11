package mockdockerd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/ioutils"
	"github.com/docker/docker/pkg/stringid"
)

const mockAPIVersion = "v1.29"

var (
	mockContextWithTimeout bool
	err                    error
	ctx                    = context.Background()
)

func testlogF(format interface{}, a ...interface{}) {
	var (
		caller string
		msg    string
	)
	_, fn, line, _ := runtime.Caller(1)
	caller = fmt.Sprintf("%s:%d", fn, line)
	s := strings.Split(caller, "/")
	caller = s[len(s)-1]

	switch format.(type) {
	case string:
		msg = fmt.Sprintf(format.(string), a...)
	default:
		msg = fmt.Sprintf("%v", format)
	}
	fmt.Printf("%s: %s \n", caller, msg)
}

func mockEvents(ctx context.Context) (*http.Response, error) {
	pr, pw := io.Pipe()
	w := ioutils.NewWriteFlusher(pw)
	msgChan := make(chan []byte)

	filters := filters.NewArgs()
	filters.Add("type", events.ContainerEventType)

	eventsCases := struct {
		options types.EventsOptions
		events  []events.Message
	}{
		options: types.EventsOptions{
			Filters: filters,
		},
		events: []events.Message{
			{
				Type:   "container",
				ID:     mockID(),
				Action: "create",
				Status: "state create",
			},
			{
				Type:   "container",
				ID:     mockID(),
				Action: "die",
				Status: "state die",
			},
			{
				Type:   "container",
				ID:     mockID(),
				Action: "destroy",
				Status: "state destroy",
			},
		},
	}
	go func() {
		for _, e := range eventsCases.events {
			b, _ := json.Marshal(e)
			msgChan <- b
			time.Sleep(1000 * time.Millisecond)
		}

	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				testlogF("Context canceld")
				w.Close()
				pw.Close()
				pr.Close()
				return
			case msg := <-msgChan:
				w.Write(msg)
			}
		}
	}()

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       pr,
	}, nil
}

func mockPing() (*http.Response, error) {
	header := http.Header{}
	header.Add("OSType", "Linux")
	header.Add("API-Version", mockAPIVersion)
	header.Add("Docker-Experimental", "true")
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
	}, nil
}

func mockDockerArchive(path string) (*http.Response, error) {
	headercontent, err := json.Marshal(types.ContainerPathStat{
		Name: path,
		Mode: 0700,
	})
	if err != nil {
		return errorMock(500, err.Error())
	}
	base64PathStat := base64.StdEncoding.EncodeToString(headercontent)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(bytes.NewReader([]byte("content"))),
		Header: http.Header{
			"X-Docker-Container-Path-Stat": []string{base64PathStat},
		},
	}, nil
}

func mockID() string {
	return stringid.GenerateRandomID()
}

func mockReadCloser(ctx context.Context, msg string) io.ReadCloser {
	pr, pw := io.Pipe()
	w := ioutils.NewWriteFlusher(pw)
	msgChan := make(chan string)

	tc := time.NewTimer(time.Second * 30)

	go func() {
		for {
			select {
			case <-tc.C:
				close(msgChan)
				return
			default:
				msgChan <- fmt.Sprintf("%s\n", msg)
				time.Sleep(1000 * time.Millisecond)
			}
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				testlogF("Error!! Context canceld!!!")
				w.Close()
				pw.Close()
				pr.Close()
				return
			case msg, ok := <-msgChan:
				if !ok {
					return
				}
				now := time.Now().Format("15:04:05")
				m := fmt.Sprintf("[%s] %s", now, msg)
				w.Write([]byte(m))
			}
		}
	}()

	return pr
}

func mockDoer(r *http.Request) (*http.Response, error) {
	var b []byte
	prefix := fmt.Sprintf("/%s", mockAPIVersion)
	path := strings.TrimPrefix(r.URL.Path, prefix)

	// get container id
	containerID := ""
	if strings.HasPrefix(path, "/containers/") {
		cid := strings.TrimPrefix(path, "/containers/")
		containerID = strings.Split(cid, "/")[0]
		if containerID == "" {
			containerID = "_"
		}
	}

	// get image id
	image := ""
	if strings.HasPrefix(path, "/images/") && r.Method == http.MethodDelete {
		id := strings.TrimPrefix(path, "/images/")
		image = strings.Split(id, "/")[0]
	}

	// mock docker responses
	switch path {
	// docker info
	case "/info":
		testlogF("mock docker info response")
		info := &types.Info{
			ID:         "daemonID",
			Containers: 3,
		}
		b, _ = json.Marshal(info)
	// just ping
	case "/_ping":
		testlogF("mock docker ping response")
		return mockPing()
	// images
	case "/images/create": // docker image pull <>:<>
		query := r.URL.Query()
		testlogF("mock docker create image: %s:%s", query.Get("fromImage"), query.Get("tag"))
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       mockReadCloser(r.Context(), "pulling image..."),
		}, nil
	case "/images/json": // docker images
		testlogF("mock docker list images")
		b, _ = json.Marshal([]types.ImageSummary{
			{ID: "image_id_1"},
			{ID: "image_id_2"},
		})
	case fmt.Sprintf("/images/%s", image): // docker images
		testlogF("mock docker remove image")
		b, _ = json.Marshal([]types.ImageDeleteResponseItem{
			{Untagged: image},
			{Deleted: image},
		})
	// containers
	case "/containers/create":
		testlogF("mock create container: %s", r.URL.Query().Get("name"))
		b, err = json.Marshal(container.ContainerCreateCreatedBody{
			ID: mockID(),
		})
	case "/containers/json":
		testlogF("mock docker ps")
		b, _ = json.Marshal([]types.Container{
			{
				ID:      mockID(),
				Names:   []string{"hello docker"},
				Image:   "test:image",
				ImageID: mockID(),
				Command: "top",
			},
		})
	case fmt.Sprintf("/containers/%s/json", containerID):
		testlogF("inspect container %s", containerID)
		b, _ = json.Marshal(types.ContainerJSON{
			ContainerJSONBase: &types.ContainerJSONBase{
				ID:    containerID,
				Image: "test:image",
				Name:  "name",
				State: &types.ContainerState{
					Running: true,
				},
				HostConfig: &container.HostConfig{
					Resources: container.Resources{
						CPUQuota:  9999,
						CPUPeriod: 9999,
						CPUShares: 999,
						Memory:    99999,
					},
				},
			},
			Config: &container.Config{
				Labels: map[string]string{
					"ERU": "1",
				},
				Image: "test:image",
			},
		})
	case fmt.Sprintf("/containers/%s", containerID):
		testlogF("remove container %s", containerID)
	case fmt.Sprintf("/containers/%s/start", containerID):
		testlogF("start container %s", containerID)
	case fmt.Sprintf("/containers/%s/stop", containerID):
		testlogF("stop container %s", containerID)
	case fmt.Sprintf("/containers/%s/archive", containerID): // docker cp
		path := r.URL.Query().Get("path")
		testlogF("mock docker cp to %s", path)
		return mockDockerArchive(path)
	case fmt.Sprintf("/containers/%s/logs", containerID): // docker logs
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       mockReadCloser(ctx, "docker logs..."),
		}, nil
	// docker network xxx
	case "/networks/bridge/disconnect":
		var disconnect types.NetworkDisconnect
		json.NewDecoder(r.Body).Decode(&disconnect)
		testlogF("mock disconnect container %s from bridge network", disconnect.Container)
	case "/networks":
		testlogF("mock list networks")
		b, _ = json.Marshal([]types.NetworkResource{
			{Name: "mock_network", Driver: "bridge"},
		})
	// docker events
	case "/events":
		testlogF("mock docker events")
		return mockEvents(r.Context())
	default:
		errMsg := fmt.Sprintf("Server Error, unknown path: %s", path)
		return errorMock(500, errMsg)
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       ioutil.NopCloser(bytes.NewReader(b)),
	}, nil
}

func newMockClient(doer func(*http.Request) (*http.Response, error)) *http.Client {
	return &http.Client{
		Transport: transportFunc(doer),
	}
}

func errorMock(statusCode int, message string) (*http.Response, error) {
	header := http.Header{}
	header.Set("Content-Type", "application/json")

	body, err := json.Marshal(&types.ErrorResponse{
		Message: message,
	})
	if err != nil {
		return nil, err
	}

	return &http.Response{
		StatusCode: statusCode,
		Body:       ioutil.NopCloser(bytes.NewReader(body)),
		Header:     header,
	}, fmt.Errorf(message)
}

// transportFunc allows us to inject a mock transport for testing. We define it
// here so we can detect the tlsconfig and return nil for only this type.
type transportFunc func(*http.Request) (*http.Response, error)

func (tf transportFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return tf(req)
}

// NewClient return a mock docker client...
func NewClient() *client.Client {
	clnt := newMockClient(mockDoer)
	c, err := client.NewClient("tcp://127.0.0.1:2333", mockAPIVersion, clnt, nil)
	if err != nil {
		testlogF(err)
		panic(err)
	}
	return c
}
