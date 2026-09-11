package main

import (
	"fmt"
	"os"

	"ExHIBITkeyfind/internal/exhibit"
)

func main() {
	for _, arg := range os.Args[1:] {
		if err := exhibit.Run(arg); err != nil {
			fmt.Println(err)
		}
	}
}
