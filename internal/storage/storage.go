package storage

import (
	"fmt"
	"os"
)

func Dump(key []byte, filename string) (err error) {
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("storage/Dump: %v", err)
	}
	defer f.Close()

	_, err = f.Write(key)
	if err != nil {
		return fmt.Errorf("storage/Dump: %v", err)
	}

	return nil
}

func Load() ([]byte, error) {
	return nil, nil
}
