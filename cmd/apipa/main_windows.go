package main

import (
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
)

// pluginVersion labels the executable's version text and can be set at build time.
var pluginVersion = "dev"

// main serves supported CNI commands and emits protocol results or errors.
func main() {
	// Callers receive CNI JSON on stdout and a nonzero exit status on failure.
	p := plugin{api: nativeAPI()}
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add:   p.add,
		Del:   p.del,
		Check: p.check,
	}, version.PluginSupports("0.4.0", "1.0.0"), "CNI plugin apipa "+pluginVersion)
}
