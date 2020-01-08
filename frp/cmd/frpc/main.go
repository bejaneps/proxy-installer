package main

import (
	"math/rand"
	"time"

	_ "github.com/bejaneps/frp/assets/frpc/statik"
	"github.com/bejaneps/frp/cmd/frpc/sub"

	"github.com/fatedier/golib/crypto"
)

func main() {
	crypto.DefaultSalt = "frp"
	rand.Seed(time.Now().UnixNano())

	sub.Execute()
}
