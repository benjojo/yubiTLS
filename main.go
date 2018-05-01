package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/prep/gpg/agent"
)

func main() {
	csrgen := flag.Bool("signcsr", false, "set to try to poop out a CSR")
	selectedkeyid := flag.String("keyid", "", "the Key ID in the agent to use")
	flag.Parse()

	options := []string{
		"allow-pinentry-notify",
		"agent-awareness=2.1.0",
	}

	conn, err := agent.Dial("/run/user/1000/gnupg/S.gpg-agent", options)

	if err != nil {
		log.Fatalf("Unable to connect to GPG agent! %s", err.Error())
	}

	key, err := conn.Key(*selectedkeyid)

	if *selectedkeyid == "" || err != nil {
		keys, err := conn.Keys()
		if err != nil {
			log.Fatalf("Unable to read keys from GPG agent! %s", err.Error())
		}

		printKeysAndFail(keys)
	}

	if *csrgen {
		GenerateCSR(key)
		os.Exit(0)
	}

	conn.Close()
}

func printKeysAndFail(keys []agent.Key) {
	fmt.Printf("You appear to have not selected a key to use, or the key you selected\n")
	fmt.Printf("Does not exist in the agent at this time, Do you see your key in this list?\n")

	for _, v := range keys {
		log.Printf("Key: %s - %+v\n", v.Keygrip, v)
	}

	os.Exit(1)
}
