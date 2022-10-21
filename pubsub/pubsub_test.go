package pubsub

import (
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
	"time"
)

func TestPubSub(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	res := "not set"
	unsub := Subscribe("test", func(data string) {
		res = data
		wg.Done()
	})
	Publish("test", "value 1")
	wg.Wait()
	require.Equal(t, "value 1", res)

	unsub()
	Publish("test", "value 2")
	time.Sleep(250 * time.Millisecond)
	require.Equal(t, "value 1", res)

	wg.Add(1)
	unsub = Subscribe("test", func(data string) {
		res = data
		wg.Done()
	})
	Publish("test", "value 3")
	wg.Wait()
	require.Equal(t, "value 3", res)
}
