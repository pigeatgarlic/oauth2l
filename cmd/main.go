package main

import (
	"fmt"
	"github.com/google/oauth2l"
)


func main() {
	token, err := oauth2l.StartAuth()
	if err != nil {
		fmt.Printf("%s", err.Error())
	} else {
		fmt.Printf("%s", token.AccessToken)
	}
}