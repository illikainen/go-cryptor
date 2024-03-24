module github.com/illikainen/go-cryptor

go 1.19

require (
	github.com/illikainen/go-netutils v0.0.0
	github.com/illikainen/go-utils v0.0.0
	github.com/pkg/errors v0.9.1
	github.com/samber/lo v1.37.0
	github.com/sirupsen/logrus v1.9.0
	github.com/spf13/pflag v1.0.5
	golang.org/x/crypto v0.14.0
)

require (
	github.com/fatih/color v1.15.0 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/pkg/sftp v1.13.5 // indirect
	golang.org/x/exp v0.0.0-20230905200255-921286631fa9 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/term v0.13.0 // indirect
)

replace github.com/illikainen/go-netutils => ../go-netutils

replace github.com/illikainen/go-utils => ../go-utils
