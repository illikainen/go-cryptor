//go:build tools

package tools

import (
	_ "github.com/gostaticanalysis/nilerr/cmd/nilerr"
	_ "github.com/kisielk/errcheck"
	_ "github.com/mgechev/revive"
	_ "github.com/securego/gosec/v2"
	_ "golang.org/x/tools/cmd/goimports"
	_ "honnef.co/go/tools/cmd/staticcheck"
)
