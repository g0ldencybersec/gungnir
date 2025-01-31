package main

import (
	"log"

	"github.com/g0ldencybersec/gungnir/pkg/runner"
)

func main() {
	options, err := runner.ParseOptions()
	if err != nil {
		log.Fatalf("Error parsing options: %v", err)
	}

	runner, err := runner.NewRunner(options)
	if err != nil {
		log.Fatalf("Error creating runner: %v", err)
	}

	runner.Run()
}
