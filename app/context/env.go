package context

// Environment is the interface to the process environment.
type Environment interface {
	Get(string) string
	Set(string, string) error
}
