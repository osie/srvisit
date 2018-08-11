package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

func main() {
	logAdd(MESS_INFO, "The reVisit version server is started "+REVISIT_VERSION)

	runtime.GOMAXPROCS(runtime.NumCPU())

	loadOptions()

	for _, x := range os.Args {
		if strings.Contains(x, "node") {
			options.Mode = NODE
		} else if strings.Contains(x, "master") {
			options.Mode = MASTER
		}
	}

	if options.Mode != NODE {
		loadVNCList()
		loadCounters()
		loadProfiles()

		go helperThread() //we use for periodic actions (conservation, etc.)
		go httpServer()   //web request processing
		go mainServer()   //processing of main commands from clients and agents
	}

	if options.Mode != MASTER {
		go dataServer() //processing of data streams from clients
	}

	if options.Mode == MASTER {
		go masterServer() //communicate with agents
	}

	if options.Mode == NODE {
		go nodeClient() //clinches connecting to the master
	}

	var r string
	for r != "quit" {
		fmt.Scanln(&r)
	}

	logAdd(MESS_INFO, "Finished work")
}
