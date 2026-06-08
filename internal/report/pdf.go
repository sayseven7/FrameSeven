package report

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	pdfPageWidth  = 612
	pdfPageHeight = 792
	pdfMargin     = 54
	pdfFontSize   = 10
	pdfLineHeight = 14
	pdfMaxColumns = 92
)

// RenderPDF returns a PDF report as bytes, matching the file the CLI writes.
func RenderPDF(rep Report) ([]byte, error) {
	var b bytes.Buffer
	if err := WritePDF(&b, rep); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// WritePDF renders a portable PDF report using the same CLI v1 text content.
func WritePDF(w io.Writer, rep Report) error {
	lines := wrapPDFLines(RenderText(rep))
	pages := paginatePDFLines(lines)
	data := buildPDFDocument(pages)

	_, err := w.Write(data)
	return err
}

func wrapPDFLines(text string) []string {
	var lines []string
	for _, line := range splitLines(text) {
		if line == "" {
			lines = append(lines, "")
			continue
		}

		lines = append(lines, wrapPDFLine(line)...)
	}

	return lines
}

func wrapPDFLine(line string) []string {
	if len(line) <= pdfMaxColumns {
		return []string{line}
	}

	var out []string
	remaining := line
	for len(remaining) > pdfMaxColumns {
		cut := pdfMaxColumns
		for cut > 0 && remaining[cut] != ' ' {
			cut--
		}

		if cut == 0 {
			cut = pdfMaxColumns
		}

		out = append(out, strings.TrimRight(remaining[:cut], " "))
		remaining = strings.TrimLeft(remaining[cut:], " ")
	}

	if remaining != "" {
		out = append(out, remaining)
	}

	return out
}

func paginatePDFLines(lines []string) [][]string {
	linesPerPage := (pdfPageHeight - (pdfMargin * 2)) / pdfLineHeight
	var pages [][]string

	for len(lines) > 0 {
		count := linesPerPage
		if len(lines) < count {
			count = len(lines)
		}

		pages = append(pages, lines[:count])
		lines = lines[count:]
	}

	if len(pages) == 0 {
		pages = append(pages, []string{})
	}

	return pages
}

func buildPDFDocument(pages [][]string) []byte {
	objectCount := 3 + len(pages)*2
	objects := make([]string, objectCount+1)
	objects[1] = "<< /Type /Catalog /Pages 2 0 R >>"

	var kids strings.Builder
	for i := range pages {
		pageObject := 3 + i*2
		fmt.Fprintf(&kids, "%d 0 R ", pageObject)
	}

	objects[2] = fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.TrimSpace(kids.String()), len(pages))

	for i, pageLines := range pages {
		pageObject := 3 + i*2
		contentObject := pageObject + 1
		objects[pageObject] = fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Courier >> >> >> /Contents %d 0 R >>", pdfPageWidth, pdfPageHeight, contentObject)

		stream := buildPDFPageStream(pageLines)
		objects[contentObject] = fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream)
	}

	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n%\xE2\xE3\xCF\xD3\n")

	offsets := make([]int, objectCount+1)
	for i := 1; i <= objectCount; i++ {
		offsets[i] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i, objects[i])
	}

	xrefOffset := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n", objectCount+1)
	out.WriteString("0000000000 65535 f \n")

	for i := 1; i <= objectCount; i++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[i])
	}

	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", objectCount+1, xrefOffset)

	return out.Bytes()
}

func buildPDFPageStream(lines []string) string {
	var stream strings.Builder
	fmt.Fprintf(&stream, "BT\n/F1 %d Tf\n%d %d Td\n", pdfFontSize, pdfMargin, pdfPageHeight-pdfMargin)

	for i, line := range lines {
		if i > 0 {
			fmt.Fprintf(&stream, "0 -%d Td\n", pdfLineHeight)
		}

		fmt.Fprintf(&stream, "(%s) Tj\n", escapePDFText(line))
	}

	stream.WriteString("ET")

	return stream.String()
}

func escapePDFText(value string) string {
	var out strings.Builder
	for _, r := range value {
		switch r {
		case '\\', '(', ')':
			out.WriteByte('\\')
			out.WriteRune(r)
		case '\t':
			out.WriteString("    ")
		default:
			if r >= 32 && r <= 126 {
				out.WriteRune(r)
			} else {
				quoted := strconv.QuoteToASCII(string(r))
				out.WriteString(quoted[1 : len(quoted)-1])
			}
		}
	}

	return out.String()
}
