# Mock Dockerd

A mock tool for local docker testing.

```golang
package main

import (
	"context"
	"fmt"

	"github.com/wrfly/mock-dockerd"
)

func main() {

	c := mockdockerd.NewClient()
	resp, err := c.Ping(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Println(resp)
}

```
