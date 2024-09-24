package runner

import "flag"

type Options struct {
	Verbose    bool
	RootList   string
	Debug      bool
	JsonOutput bool
	WatchFile  bool
}

func ParseOptions() *Options {
	options := &Options{}

	flag.StringVar(&options.RootList, "r", "", "Path to the list of root domains to filter against")
	flag.BoolVar(&options.WatchFile, "f", false, "Monitor the root domain file for updates and add the new roots to the scan")
	flag.BoolVar(&options.Verbose, "v", false, "Output go logs (500/429 errors) to command line")
	flag.BoolVar(&options.Debug, "debug", false, "Debug CT logs to see if you are keeping up")
	flag.BoolVar(&options.JsonOutput, "j", false, "JSONL output cert info")
	flag.Parse()

	return options
}
