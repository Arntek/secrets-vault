// Command secrets-vault is the vault CLI. It is installed as secrets-vault
// with the short names vault and sv pointing at it.
package main

import (
	"os"

	"github.com/Arntek/secrets-vault/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args, os.Stdin, os.Stdout, os.Stderr))
}
