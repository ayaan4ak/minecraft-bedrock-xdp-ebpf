package utils

import (
	"log"
)

func IfError(err error, part string) {
	if err != nil {
		log.Printf("\033[31m[%s] \033[0mError: \033[31m%s\033[0m\n", part, err)
	}
}
