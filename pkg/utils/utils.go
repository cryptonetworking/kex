package utils

func Throw(e error) {
	if e != nil {
		panic(e)
	}
}

func Must[R any](r R, e error) R {
	Throw(e)
	return r
}
