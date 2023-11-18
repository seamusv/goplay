package pubsub

import (
	"fmt"
	"github.com/matoous/go-nanoid/v2"
	"sync"
)

var mTopicBus = map[string]any{}
var mTopicType = map[string]any{}

type Bus[T any] struct {
	Topic string
	Subs  map[string]map[string]chan T
	mu    sync.RWMutex
}

func Subscribe[T any](topic string, fn func(data T)) func() {
	if typ, ok := mTopicType[topic]; ok {
		switch typ.(type) {
		case T:
		default:
			fmt.Printf("Subscribe on %s: expected data type to be %T got %T \n", topic, typ, *new(T))
			return nil
		}
	} else {
		mTopicType[topic] = *new(T)
	}
	var b *Bus[T]
	if topicbus, ok := mTopicBus[topic]; ok {
		if bb, ok := topicbus.(*Bus[T]); ok {
			b = bb
		}
	} else {
		b = &Bus[T]{
			Topic: topic,
			Subs:  make(map[string]map[string]chan T),
		}
		mTopicBus[topic] = b
	}
	guid := gonanoid.Must(8)
	ch := make(chan T)
	b.mu.Lock()
	if _, found := b.Subs[topic]; found {
		b.Subs[topic][guid] = ch
	} else {
		b.Subs[topic] = map[string]chan T{guid: ch}
	}
	b.mu.Unlock()

	go func() {
		for v := range ch {
			fn(v)
		}
	}()

	return func() {
		b.mu.Lock()
		ch, ok := b.Subs[topic][guid]
		if ok {
			close(ch)
			delete(b.Subs[topic], guid)
		}
		b.mu.Unlock()
	}
}

func Publish[T any](topic string, data T) {
	var b *Bus[T]
	if topicbus, ok := mTopicBus[topic]; ok {
		if bb, ok := topicbus.(*Bus[T]); ok {
			b = bb
		} else {
			fmt.Printf("Publish on %s doesn't match data type: want %T got %T\n", topic, mTopicType[topic], *new(T))
			return
		}
	} else {
		b = &Bus[T]{
			Topic: topic,
			Subs:  make(map[string]map[string]chan T),
		}
		mTopicBus[topic] = b
	}
	b.mu.RLock()
	if mChans, found := b.Subs[topic]; found {
		// create copy of channels to avoid copy reference
		var channels []chan T
		for _, c := range mChans {
			channels = append(channels, c)
		}
		go func(data T, dataChannels []chan T) {
			for _, ch := range dataChannels {
				ch <- data
			}
		}(data, channels)
	}
	b.mu.RUnlock()
}
