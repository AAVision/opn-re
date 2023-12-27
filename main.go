package main

import (
	"time"

	"github.com/alexflint/go-arg"
	"github.com/gookit/color"
)

type UserInput struct {
	Domain  string `arg:"-d"`
	Force   bool   `arg:"-f"`
	Xss     bool   `arg:"-x"`
	Simple  bool   `arg:"-s"`
	Input   string `arg:"-i"`
	Verbose bool   `arg:"-v"`
}

func main() {
	userInput := UserInput{}
	arg.MustParse(&userInput)

	start := time.Now()

	err := starter(userInput)

	if err != nil {
		color.Errorln("Error:", err)
	}

	duration := time.Since(start)
	color.Cyanln("Finished in:", duration)
}
