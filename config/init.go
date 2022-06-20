package config

import (
	"runtime"

	"github.com/gofiber/fiber/v2"
	"github.com/spf13/viper"

	"auth-service/internal/log"
)

func Init() error {
	viper.AddConfigPath("./config")
	viper.SetConfigName("config")

	return viper.ReadInConfig()
}

// Runtime sets the number of operating system threads
func Runtime() {
	NumCPU := runtime.GOMAXPROCS(runtime.NumCPU())

	if !fiber.IsChild() {
		log.Info.Printf("Running with %d CPUs\n", NumCPU)
	}
}
