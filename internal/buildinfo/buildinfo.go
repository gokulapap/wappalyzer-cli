package buildinfo

import "runtime"

// These values are replaced by release builds through -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuiltAt   string `json:"built_at"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

func Current() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuiltAt:   Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}
