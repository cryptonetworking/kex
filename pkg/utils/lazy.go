package utils

import (
	"sync"
)

type Lazy[V any] struct {
	fn   func() (V, error)
	v    V
	e    error
	once sync.Once
}

func (l *Lazy[V]) Get() (V, error) {
	l.once.Do(func() {
		l.v, l.e = l.fn()
	})
	return l.v, l.e
}

func NewLazy[V any](fn func() (V, error)) *Lazy[V] {
	return &Lazy[V]{fn: fn}
}
