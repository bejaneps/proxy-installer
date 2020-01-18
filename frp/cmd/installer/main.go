package main

func main() {
	rootCmd.AddCommand(cmdRCA, cmdRSA)

	Execute()
}
