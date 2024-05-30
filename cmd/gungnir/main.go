package main

import (
	"github.com/g0ldencybersec/gungnir/pkg/runner"
)

func main() {
	options := runner.ParseOptions()
	runner, err := runner.NewRunner(options)
	if err != nil {
		panic(err)
	}

	runner.Run()
}
