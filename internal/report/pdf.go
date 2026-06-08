package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

import _ "embed"

//go:embed pdf.py
var pdfScriptV1 string

// RenderPDF returns a PDF report as bytes, matching the file the CLI writes.
func RenderPDF(rep Report) ([]byte, error) {
	data, err := json.Marshal(rep)
	if err != nil {
		return nil, fmt.Errorf("encode report for PDF: %w", err)
	}

	python := pdfPython()
	cmd := exec.Command(python, "-c", pdfScriptV1) // #nosec G204 - pdfScriptV1 is embedded at compile time via //go:embed; only the Python interpreter path is configurable
	cmd.Stdin = bytes.NewReader(data)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, pdfRenderError(python, err, stderr.String())
	}

	return stdout.Bytes(), nil
}

// WritePDF renders a portable PDF report using the Python PDF renderer v1.
func WritePDF(w io.Writer, rep Report) error {
	data, err := RenderPDF(rep)
	if err != nil {
		return err
	}

	_, err = w.Write(data)
	return err
}

func pdfPython() string {
	if value := os.Getenv("FRAMESEVEN_PYTHON"); value != "" {
		return value
	}

	for _, dir := range candidatePythonDirs() {
		venvPython := filepath.Join(dir, ".venv", "bin", "python")
		if _, err := os.Stat(venvPython); err == nil {
			return venvPython
		}
	}

	return "python3"
}

func candidatePythonDirs() []string {
	var dirs []string

	dir, err := os.Getwd()
	if err != nil {
		return []string{"."}
	}

	for {
		dirs = append(dirs, dir)

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}

		dir = parent
	}

	return dirs
}

func pdfRenderError(python string, err error, stderr string) error {
	stderr = strings.TrimSpace(stderr)
	if errors.Is(err, exec.ErrNotFound) {
		return fmt.Errorf("render PDF with Python: Python interpreter %q was not found; install Python 3 or set FRAMESEVEN_PYTHON", python)
	}

	if strings.Contains(stderr, "fpdf2 is required") || strings.Contains(stderr, "ModuleNotFoundError: No module named 'fpdf'") {
		return fmt.Errorf("render PDF with Python: fpdf2 is not installed for %q; install it with python3 -m pip install fpdf2 or set FRAMESEVEN_PYTHON: %s", python, stderr)
	}

	if stderr != "" {
		return fmt.Errorf("render PDF with Python: %w: %s", err, stderr)
	}

	return fmt.Errorf("render PDF with Python: %w", err)
}
