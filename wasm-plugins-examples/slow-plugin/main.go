// Deliberately misbehaving plugin used to verify the host enforces its
// execution timeout independently of plugin logic. It busy-loops forever.
package main

func main() {
	for {
	}
}
