package main

import (
	"time"

	"github.com/alexflint/go-arg"
	"github.com/gookit/color"
)

type UserInput struct {
	Domain string `arg:"-d,required"`
	J      bool   `arg:"-j"`
	Force  bool   `arg:"-f"`
	Xss    bool   `arg:"-x"`
	Quiet  bool   `arg:"-q"`
	Single bool   `arg:"-s"`
	Input  string `arg:"-i"`
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
