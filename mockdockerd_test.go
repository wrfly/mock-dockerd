package mockdockerd

import (
	"bufio"
	"context"
	"io"
	"io/ioutil"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/stretchr/testify/assert"
)

func scanReadCloser(rc io.ReadCloser, timeout int) {
	scanner := bufio.NewScanner(rc)
	t := time.NewTimer(time.Duration(timeout) * time.Second)
	for {
		select {
		case <-t.C:
			t.Stop()
			return
		default:
			if scanner.Scan() {
				testlogF(scanner.Text())
			}
		}
	}
}

func TestPing(t *testing.T) {
	c := NewClient()
	resp, err := c.Ping(ctx)
	assert.NoError(t, err)
	t.Log(resp)
}

func TestEvents(t *testing.T) {
	c := NewClient()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	eventChan, errChan := c.Events(ctx, types.EventsOptions{})

	for {
		select {
		case err := <-errChan:
			assert.Equal(t, err, io.ErrClosedPipe)
			return
		case event := <-eventChan:
			testlogF("ID: %s, Action: %s, Status: %s", event.ID, event.Action, event.Status)
		}
	}
}

func TestLogs(t *testing.T) {
	c := NewClient()
	rc, err := c.ContainerLogs(ctx, "containerID", types.ContainerLogsOptions{})
	assert.NoError(t, err)
	scanReadCloser(rc, 5)
}

func TestContainerActions(t *testing.T) {
	c := NewClient()

	// docker ps
	containers, err := c.ContainerList(ctx, types.ContainerListOptions{})
	assert.NoError(t, err)
	containerID := containers[0].ID
	assert.Equal(t, len(containerID), 64)

	// docker inspect
	r, err := c.ContainerInspect(ctx, containerID)
	assert.NoError(t, err)
	assert.Equal(t, r.ID, containerID)

	// start/stop/remove container
	err = c.ContainerStart(ctx, containerID, types.ContainerStartOptions{})
	assert.NoError(t, err)
	td := time.Second * 5
	err = c.ContainerStop(ctx, containerID, &td)
	assert.NoError(t, err)
	err = c.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{})
	assert.NoError(t, err)

	// docker cp xxx xxx
	rc, path, err := c.CopyFromContainer(ctx, containerID, "/root/src")
	assert.NoError(t, err)
	assert.Equal(t, path.Name, "/root/src")
	b, err := ioutil.ReadAll(rc)
	testlogF("%s", b)
}

func TestImages(t *testing.T) {
	c := NewClient()

	rc, err := c.ImagePull(ctx, "ubuntu:latest", types.ImagePullOptions{})
	assert.NoError(t, err)
	scanReadCloser(rc, 3)

	items, err := c.ImageRemove(ctx, "ubuntu:latest", types.ImageRemoveOptions{})
	testlogF(items)
}
