package main

import (
	"fmt"

	"github.com/pigeatgarlic/oauth2l"
)

type data struct {
	Hello string `json:"hello"`
}

func main() {
	token, err := oauth2l.StartAuth(data{
		Hello: "adf",
	})
	if err != nil {
		fmt.Printf("%s", err.Error())
	} else {
		fmt.Printf("Username: %s \nPassword: %s \n", token.Username, token.Password)
	}
}
