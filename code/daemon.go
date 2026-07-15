package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var (
	openCanaryCommand = "/opt/opencanary/bin/twistd"
	openCanaryTac     = "/opt/opencanary/bin/opencanary.tac"
	openCanaryPIDFile = "/run/opencanary/opencanaryd.pid"
)

type DaemonStatus struct {
	Running       bool
	PID           int       `json:",omitempty"`
	StartedAt     time.Time `json:",omitempty"`
	UptimeSeconds int64
	LastError     string `json:",omitempty"`
	Version       string
	CanaryIP      string
}

type DaemonManager struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	done      chan struct{}
	startedAt time.Time
	lastError string
}

func ensureTLSCertificate() error {
	if _, certErr := os.Stat(TLSCertFile); certErr == nil {
		if _, keyErr := os.Stat(TLSKeyFile); keyErr == nil {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(TLSCertFile), 0750); err != nil {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "spr-canary.local", Organization: []string{"SPR OpenCanary"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"spr-canary.local", "localhost"},
	}
	if ip := net.ParseIP(canaryIP()); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := atomicWrite(TLSCertFile, certPEM, 0644); err != nil {
		return err
	}
	if err := atomicWrite(TLSKeyFile, keyPEM, 0600); err != nil {
		return err
	}
	return nil
}

func prepareEventLog() error {
	if err := os.MkdirAll(filepath.Dir(EventLogFile), 0770); err != nil {
		return err
	}
	sshKeyDir := testPrefix + stateDir + "/ssh"
	if err := os.MkdirAll(sshKeyDir, 0750); err != nil {
		return err
	}
	file, err := os.OpenFile(EventLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0660)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// OpenCanary drops to nobody:nogroup after binding privileged ports.
	// Ownership lets its file handler append alerts after the privilege drop.
	_ = os.Chown(filepath.Dir(EventLogFile), 65534, 65534)
	_ = os.Chown(EventLogFile, 65534, 65534)
	_ = os.Chown(filepath.Dir(TLSCertFile), 65534, 65534)
	_ = os.Chown(TLSCertFile, 65534, 65534)
	_ = os.Chown(TLSKeyFile, 65534, 65534)
	_ = os.Chown(sshKeyDir, 65534, 65534)
	return nil
}

func hardenSSHPrivateKeys() {
	sshKeyDir := testPrefix + stateDir + "/ssh"
	for attempt := 0; attempt < 20; attempt++ {
		ready := true
		for _, name := range []string{"id_rsa", "id_dsa"} {
			if err := os.Chmod(filepath.Join(sshKeyDir, name), 0600); err != nil {
				if !os.IsNotExist(err) {
					fmt.Println("warning: could not harden SSH host key:", err)
				}
				ready = false
			}
		}
		if ready {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (m *DaemonManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil && m.cmd.ProcessState == nil {
		return nil
	}
	if err := ensureTLSCertificate(); err != nil {
		return fmt.Errorf("prepare TLS certificate: %w", err)
	}
	if err := prepareEventLog(); err != nil {
		return fmt.Errorf("prepare event log: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(openCanaryPIDFile), 0750); err != nil {
		return fmt.Errorf("prepare OpenCanary runtime directory: %w", err)
	}
	if err := os.Chown(filepath.Dir(openCanaryPIDFile), 65534, 65534); err != nil {
		return fmt.Errorf("own OpenCanary runtime directory: %w", err)
	}
	// The daemon drops privileges after creating its PID file, so it cannot
	// always remove a stale root-owned file. The supervisor owns its lifecycle.
	if err := os.Remove(openCanaryPIDFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale OpenCanary PID file: %w", err)
	}
	processLog, err := os.OpenFile(ProcessLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("open daemon log: %w", err)
	}

	// Supervise twistd directly. The upstream opencanaryd shell wrapper receives
	// SIGTERM alongside its child when a process group is stopped, which can
	// orphan a zombie and make fast configuration restarts fail.
	cmd := exec.Command(
		openCanaryCommand,
		"-noy", openCanaryTac,
		"--pidfile", openCanaryPIDFile,
		"--uid=nobody", "--gid=nogroup",
	)
	cmd.Dir = filepath.Dir(OpenCanaryConfig)
	cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")
	cmd.Stdout = io.MultiWriter(os.Stdout, processLog)
	cmd.Stderr = io.MultiWriter(os.Stderr, processLog)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		processLog.Close()
		m.lastError = err.Error()
		return fmt.Errorf("start OpenCanary: %w", err)
	}
	// OpenCanary creates its private host keys with the process umask. Tighten
	// their permissions after first generation and again on every start.
	go hardenSSHPrivateKeys()

	done := make(chan struct{})
	m.cmd = cmd
	m.done = done
	m.startedAt = time.Now().UTC()
	m.lastError = ""
	go func() {
		err := cmd.Wait()
		processLog.Close()
		m.mu.Lock()
		if m.cmd == cmd {
			m.cmd = nil
			if err != nil {
				m.lastError = err.Error()
			}
		}
		close(done)
		m.mu.Unlock()
	}()
	return nil
}

func (m *DaemonManager) Stop() error {
	m.mu.Lock()
	cmd := m.cmd
	done := m.done
	if cmd == nil || cmd.Process == nil {
		m.mu.Unlock()
		return nil
	}
	pid := cmd.Process.Pid
	m.mu.Unlock()

	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil && err != syscall.ESRCH {
		return err
	}
	select {
	case <-done:
		_ = os.Remove(openCanaryPIDFile)
		return nil
	case <-time.After(6 * time.Second):
		if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
			return err
		}
		select {
		case <-done:
			_ = os.Remove(openCanaryPIDFile)
			return nil
		case <-time.After(2 * time.Second):
			return fmt.Errorf("OpenCanary process group %d did not exit", pid)
		}
	}
}

func (m *DaemonManager) Restart() error {
	if err := m.Stop(); err != nil {
		return err
	}
	return m.Start()
}

func (m *DaemonManager) Status() DaemonStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	status := DaemonStatus{
		Version:   openCanaryVer,
		CanaryIP:  canaryIP(),
		LastError: m.lastError,
	}
	if m.cmd != nil && m.cmd.Process != nil && m.cmd.ProcessState == nil {
		status.Running = true
		status.PID = m.cmd.Process.Pid
		status.StartedAt = m.startedAt
		status.UptimeSeconds = int64(time.Since(m.startedAt).Seconds())
	}
	return status
}
