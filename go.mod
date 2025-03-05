module go.pennock.tech/fingerd

// If bumping this, be sure to check CI workflows too
go 1.23.0

toolchain go1.24.1

require (
	github.com/sirupsen/logrus v1.9.3
	gopkg.in/fsnotify.v1 v1.4.7
)

require (
	github.com/fsnotify/fsnotify v1.4.7 // indirect
	golang.org/x/sys v0.31.0 // indirect
)
