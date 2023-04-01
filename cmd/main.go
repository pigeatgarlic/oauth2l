package main

import (
	"fmt"

	"github.com/pigeatgarlic/oauth2l"
)

type data struct {
	Hello string `json:"hello"`
}

func main() {
	token, err := oauth2l.StartAuth("610452128706-s8auiqjknom5t225s2bn94dctpambeei.apps.googleusercontent.com",3000)
	if err != nil {
		return 
	}
	fmt.Printf(token)
}
