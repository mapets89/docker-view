package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dockerview/dockerview/backend/internal/config"
	"github.com/dockerview/dockerview/backend/internal/database"
	"golang.org/x/term"
)

func runBootstrap(args []string, stdin *os.File, stdout io.Writer) error {
	flags := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	flags.SetOutput(stdout)
	username := flags.String("username", "", "initial administrator username")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*username) == "" {
		return errors.New("usage: dockerview-server bootstrap --username USERNAME")
	}
	password, err := readHiddenPassword(stdin, stdout, "Password: ")
	if err != nil {
		return err
	}
	confirmation, err := readHiddenPassword(stdin, stdout, "Confirm password: ")
	if err != nil {
		return err
	}
	if password != confirmation {
		return errors.New("passwords do not match")
	}
	cfg, err := config.Load("recovery")
	if err != nil {
		return err
	}
	store, err := database.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = store.Close() }()
	user, err := store.BootstrapAdmin(context.Background(), strings.TrimSpace(*username), password)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Administrator created: %s\n", user.Username)
	return err
}

func runPasswordRecovery(args []string, stdin *os.File, stdout io.Writer) error {
	flags := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	flags.SetOutput(stdout)
	username := flags.String("username", "", "local username to recover")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*username) == "" {
		return errors.New("usage: dockerview-server reset-password --username USERNAME")
	}
	password, err := readHiddenPassword(stdin, stdout, "New password: ")
	if err != nil {
		return err
	}
	confirmation, err := readHiddenPassword(stdin, stdout, "Confirm password: ")
	if err != nil {
		return err
	}
	if password != confirmation {
		return errors.New("passwords do not match")
	}
	cfg, err := config.Load("recovery")
	if err != nil {
		return err
	}
	store, err := database.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = store.Close() }()
	user, err := store.RecoverPassword(context.Background(), strings.TrimSpace(*username), password)
	if err != nil {
		return err
	}
	if _, err = fmt.Fprintf(stdout, "Password reset for %s. All existing sessions were revoked.\n", user.Username); err != nil {
		return fmt.Errorf("write recovery confirmation: %w", err)
	}
	return nil
}

func readHiddenPassword(stdin *os.File, stdout io.Writer, prompt string) (string, error) {
	fd := int(stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("an interactive terminal is required; do not pass passwords through pipes or command arguments")
	}
	if _, err := fmt.Fprint(stdout, prompt); err != nil {
		return "", err
	}
	value, err := term.ReadPassword(fd)
	_, _ = fmt.Fprintln(stdout)
	if err != nil {
		return "", err
	}
	password := string(value)
	for index := range value {
		value[index] = 0
	}
	return password, nil
}
