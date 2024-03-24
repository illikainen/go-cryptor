//go:build tools

// Small wrapper for `gosec` to avoid some of the dependencies that's used by
// its default CLI.

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/rules"
)

func main() {
	exclude_dir := flag.String("exclude-dir", "", "Directory to exclude")
	_ = flag.Bool("quiet", false, "Noop for compatibility")
	flag.Parse()

	analyzer := gosec.NewAnalyzer(
		nil,                        // config
		true,                       // include tests
		false,                      // don't exclude generated
		true,                       // include suppression information
		runtime.NumCPU(),           // concurrency
		log.New(io.Discard, "", 0), // logger
	)
	rules := rules.Generate(true)
	analyzer.LoadRules(rules.RulesInfo())

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("%s", err)
	}

	exclude_dirs := []string{".git", "vendor"}
	if *exclude_dir != "" {
		exclude_dirs = append(exclude_dirs, strings.TrimPrefix(*exclude_dir, cwd+string(os.PathSeparator)))
	}

	pkgs := []string{}
	for _, arg := range flag.Args() {
		pkg, err := gosec.PackagePaths(arg, gosec.ExcludedDirsRegExp(exclude_dirs))
		if err != nil {
			log.Fatalf("%s", err)
		}
		pkgs = append(pkgs, pkg...)
	}

	err = analyzer.Process([]string{}, pkgs...)
	if err != nil {
		log.Fatalf("%s", err)
	}

	issues, _, errors := analyzer.Report()
	count := 0
	for _, issue := range issues {
		if len(issue.Suppressions) > 0 {
			continue
		}

		cwe := "N/A"
		if issue.Cwe != nil && issue.Cwe.ID != "" {
			cwe = issue.Cwe.ID
		}

		fmt.Fprintf(
			os.Stderr,
			"%s:%s:%s: %s (Rule:%s, Severity:%s, Confidence:%s, CWE:%s)\n",
			strings.TrimPrefix(issue.File, cwd+string(os.PathSeparator)),
			issue.Line,
			issue.Col,
			issue.What,
			issue.RuleID,
			issue.Severity,
			issue.Confidence,
			cwe,
		)
		count++
	}

	if count > 0 || len(errors) > 0 {
		os.Exit(1)
	}
}
