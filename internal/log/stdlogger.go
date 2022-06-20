package log

import (
	"log"
	"os"
)

var (
	Info  = log.New(os.Stdout, "INFO  ", log.Ldate|log.Ltime)
	Error = log.New(os.Stderr, "ERROR ", log.Ldate|log.Ltime|log.Lshortfile)
)
