package main

import (
	"bufio"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/alecthomas/kingpin"
	"github.com/percona/go-mysql/query"
)

const (
	replaceString int = iota
	replaceFunc
)

var (
	inputFile  = kingpin.Flag("input-file", "Input file. If not specified, the input will be Stdin.").String()
	outputFile = kingpin.Flag("outout-file", "Output file. If not specified, the input will be Stdout.").String()
)

type replacer struct {
	Regex        string
	ReplaceType  int
	ReplaceRegex string
	ReplaceFunc  func(string) string
}

func main() {
	kingpin.Parse()

	var err error
	ifh := os.Stdin
	ofh := os.Stdout

	if *inputFile != "" {
		ifh, err = os.Open(*inputFile)
		if err != nil {
			log.Printf("Cannot open %q for reading: %s\n", *inputFile, err)
			os.Exit(1)
		}
	}

	if *outputFile != "" {
		ifh, err = os.Create(*outputFile)
		if err != nil {
			log.Printf("Cannot create output file %q: %s\n", *outputFile, err)
			os.Exit(1)
		}
	}

	lines, err := readFile(ifh)
	if err != nil {
		log.Fatal(err)
	}

	lines = sanitizeQueryLines(lines)
	for _, line := range lines {
		if _, err := ofh.WriteString(line + "\n"); err != nil {
			log.Fatalf("Cannot write output file %s", err)
		}
	}

}

func readFile(fh *os.File) ([]string, error) {
	lines := []string{}
	reader := bufio.NewReader(fh)

	line, err := reader.ReadString('\n')
	for err == nil {
		lines = append(lines, strings.TrimRight(line, "\n"))
		line, err = reader.ReadString('\n')
	}
	return lines, nil
}

func sanitizeQueryLines(lines []string) []string {
	inQuery := false
	joined := []string{}
	queryString := ""

	for _, line := range lines {
		if mightBeAQuery(line) {
			inQuery = true
		}
		if inQuery {
			queryString += line
			if !strings.HasSuffix(strings.TrimSpace(line), ";") {
				queryString += "\n"
				continue
			}
			inQuery = false
			queryString = query.Fingerprint(queryString)
			joined = append(joined, queryString)
			queryString = ""
			continue
		}
		joined = append(joined, line)
	}
	return joined
}

func mightBeAQuery(query string) bool {
	regexes := []*regexp.Regexp{
		regexp.MustCompile("^(?i)CREATE (TABLE|VIEW|DEFINER)"),
		regexp.MustCompile("^(?i)DROP (DATABASE|TABLE|VIEW|DEFINER)"),
		regexp.MustCompile("^(?i)INSERT INTO"),
		regexp.MustCompile("^(?i)REPLACE INTO"),
		regexp.MustCompile("^(?i)UPDATE"),
		regexp.MustCompile("^(?i)SELECT.*FROM.*"),
		regexp.MustCompile("^(?i)SET "),
		regexp.MustCompile("^(?i)SHOW TABLES"),
		regexp.MustCompile("^(?i)SHOW DATABASES"),
		regexp.MustCompile("^(?i)COMMIT"),
		regexp.MustCompile("^(?i)LOAD DATA"),
	}
	for _, re := range regexes {
		if re.MatchString(query) {
			return true
		}
	}

	return false
}
