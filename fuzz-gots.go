package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Comcast/gots/ebp"
	"github.com/Comcast/gots/packet"
	"github.com/Comcast/gots/packet/adaptationfield"
	"github.com/Comcast/gots/psi"
	"github.com/Comcast/gots/scte35"
)

// main parses a ts file that is provided with the -f flag
func Fuzz(data byte[]) int {
	// Verify if sync-byte is present and seek to the first sync-byte
	reader := bufio.NewReader(data)
	_, err = packet.Sync(reader)
	if err != nil {
		fmt.Println(err)
		return
	}
	pat, err := psi.ReadPAT(reader)
	if err != nil {
		fmt.Println(err)
		return
	}
	printPat(pat)
	fmt.Println()
	return 0
}

func printPmt(pn uint16, pmt psi.PMT) {
	fmt.Printf("Program #%v PMT\n", pn)
	fmt.Printf("\tPIDs %v\n", pmt.Pids())
	fmt.Println("\tElementary Streams")

	for _, es := range pmt.ElementaryStreams() {
		fmt.Printf("\t\tPid %v: StreamType %v: %v\n", es.ElementaryPid(), es.StreamType(), es.StreamTypeDescription())

		for _, d := range es.Descriptors() {
			fmt.Printf("\t\t\t%+v\n", d)
		}
	}
}

func printPat(pat psi.PAT) {
	fmt.Println("Pat")
	fmt.Printf("\tPMT PIDs %v\n", pat.ProgramMap())
	fmt.Printf("\tNumber of Programs %v\n", pat.NumPrograms())
}
