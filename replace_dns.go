package main

import (
	"os"
	"os/exec"
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
		config.Logger.Fatal().Msg("No DNS config found")
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
			config.Logger.Error().Err(err).Msg("Error stopping systemd-resolved")
		}
		config.Logger.Debug().Msg("Stopped systemd-resolved")
	}

	// Backup config file
	cmd := exec.Command("/bin/sh", "-c", "sudo cp "+configPath+" "+configPath+".bak")

	err := cmd.Run()
	if err != nil {
		config.Logger.Error().Err(err).Msg("Error backing up " + configPath)
	}

	// Content for systemd
	if systemDRunning {
		fileContent = "'[Resolve]\nDNS=" + config.Host + "\nDomains=~.\n'"
	} else {
		fileContent = "nameserver " + config.Host
	}
	config.Logger.Debug().Msg("Writing to " + configPath + ":")

	// Write new content
	cmd = exec.Command("sudo", "sh", "-c", "echo "+fileContent+" > "+configPath)
	cmd.Run()

	if err != nil {
		config.Logger.Error().Err(err).Msg("Error writing to " + configPath)
	}
	config.Logger.Debug().Msg("Wrote to " + configPath)

	// Restart SystemD
	if systemDRunning {
		cmd = exec.Command("/bin/sh", "-c", "sudo systemctl restart systemd-resolved")

		err = cmd.Run()
		if err != nil {
			config.Logger.Error().Err(err).Msg("Error restarting systemd-resolved")
		}
		config.Logger.Debug().Msg("Restarted systemd-resolved")

		// Fush the DNS cache
		cmd = exec.Command("/bin/sh", "-c", "sudo resolvectl flush-caches")

		err = cmd.Run()
		if err != nil {
			config.Logger.Error().Err(err).Msg("Error flushing DNS cache")
		}
		config.Logger.Debug().Msg("Flushed DNS cache")
	}
}

// restoreDNS puts back the DNS config that replaceDNS backed up, so the
// runner can resolve names again once the proxy stops.
func restoreDNS(config *Config) {
	systemDRunning := true
	if _, err := os.Stat(systemDResolvedPath); os.IsNotExist(err) {
		systemDRunning = false
	}

	configPath := resolvePath
	if systemDRunning {
		configPath = systemDResolvedPath
	}

	if _, err := os.Stat(configPath + ".bak"); err != nil {
		config.Logger.Error().Err(err).Msg("No backup of " + configPath + " to restore")
		return
	}

	if err := exec.Command("sudo", "cp", configPath+".bak", configPath).Run(); err != nil {
		config.Logger.Error().Err(err).Msg("Error restoring " + configPath)
		return
	}
	config.Logger.Debug().Msg("Restored " + configPath)

	if systemDRunning {
		if err := exec.Command("sudo", "systemctl", "restart", "systemd-resolved").Run(); err != nil {
			config.Logger.Error().Err(err).Msg("Error restarting systemd-resolved")
		}
		if err := exec.Command("sudo", "resolvectl", "flush-caches").Run(); err != nil {
			config.Logger.Error().Err(err).Msg("Error flushing DNS cache")
		}
	}
}
