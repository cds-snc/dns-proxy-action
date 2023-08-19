package main

import (
	"os"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

const (
	dockerConfigPath    = "/etc/docker/daemon.json"
	dockerDNSServer     = "172.17.0.1"
	resolvePath         = "/etc/resolv.conf"
	systemDResolvedPath = "/etc/systemd/resolved.conf"
)

func replaceDNS(config *Config) {

	// Replace Systemd DNS
	replaceResolveDNS(config)

}

func replaceResolveDNS(config *Config) {

	systemDRunning := true
	resolvePathExists := true
	var configPath string
	var fileContent string

	// Check if systemd-resolved is running
	if _, err := os.Stat(systemDResolvedPath); os.IsNotExist(err) {
		systemDRunning = false
	}

	// Check if /etc/resolv.conf exists
	if _, err := os.Stat(resolvePath); os.IsNotExist(err) {
		resolvePathExists = false
	}

	if !systemDRunning && !resolvePathExists {
		log.Fatalln("No DNS configuration found")
	}

	// Priority: systemd-resolved > /etc/resolv.conf
	if systemDRunning {
		configPath = systemDResolvedPath
	} else {
		configPath = resolvePath
	}

	// Turn off systemd-resolved if it is running
	if systemDRunning {
		// Stop systemd-resolved
		cmd := exec.Command("/bin/sh", "-c", "sudo systemctl stop systemd-resolved")

		err := cmd.Run()
		if err != nil {
			log.Errorln("Error stopping systemd-resolved:", err)
		}
		log.Debugln("Stopped systemd-resolved")
	}

	// Backup config file
	cmd := exec.Command("/bin/sh", "-c", "sudo cp "+configPath+" "+configPath+".bak")

	err := cmd.Run()
	if err != nil {
		log.Errorln("Error backing up", configPath, ":", err)
	}

	// Content for systemd
	if systemDRunning {
		fileContent = "[Resolve]\nDNS=" + config.Host + "\nDomains=~.\n"
	} else {
		fileContent = "nameserver " + config.Host
	}

	// Write new content
	cmd = exec.Command("sudo", "sh", "-c", "echo "+fileContent+" > "+configPath)
	cmd.Run()

	if err != nil {
		log.Errorln("Error writing to "+configPath+":", err)
	}
	log.Debugln("Wrote to " + configPath)

	// Restart SystemD
	if systemDRunning {
		cmd = exec.Command("/bin/sh", "-c", "sudo systemctl restart systemd-resolved")

		err = cmd.Run()
		if err != nil {
			log.Errorln("Error restarting systemd-resolved")
		}
		log.Debugln("Restarted systemd-resolved")

		// Fush the DNS cache
		cmd = exec.Command("/bin/sh", "-c", "sudo resolvectl flush-caches")

		err = cmd.Run()
		if err != nil {
			log.Errorln("Error flushing DNS cache")
		}
		log.Debugln("Flushed DNS cache")
}
