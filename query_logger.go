package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

type QueryLogger struct {
	config *Config
}

func (w QueryLogger) Write(p []byte) (n int, err error) {
	var evt map[string]interface{}
	d := json.NewDecoder(bytes.NewReader(p))
	d.UseNumber()
	err = d.Decode(&evt)
	if err != nil {
		return n, fmt.Errorf("cannot decode event: %s", err)
	}
	if evt["domain"] != nil {
		file, err := os.OpenFile(w.config.QueryLogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("Error opening file:", err)
			return 0, err
		}
		defer file.Close() // Ensure the file is closed when done
		_, err = file.Write(p)
		if err != nil {
			fmt.Println("Error writing to file:", err)
			return 0, err
		}
	}
	return len(p), nil
}
