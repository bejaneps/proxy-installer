package main

import (
	"math/rand"
	"time"

	"github.com/fatedier/golib/crypto"

	_ "github.com/bejaneps/frp/assets/frps/statik"
)

func main() {
	crypto.DefaultSalt = "frp"
	rand.Seed(time.Now().UnixNano())

	Execute()
}
