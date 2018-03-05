package main

import (
	"fmt"
	"testing"
)

func TestJoiner(t *testing.T) {
	lines, _ := readFile("/home/karl/slow_80.log")

	joined := joinQueryLines(lines)
	for _, line := range joined {
		fmt.Println(line)

	}
}
