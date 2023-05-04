package storage

import (
	"fmt"
	"os"
)

func Dump(key []byte, filename string) (err error) {
	err = os.WriteFile(filename, key, 0600)
	if err != nil {
		return fmt.Errorf("storage/Dump: %v", err)
	}

	return
}

func Load(filename string) (key []byte, err error) {
	key, err = os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("storage/Load: %v", err)
	}

	return
}
