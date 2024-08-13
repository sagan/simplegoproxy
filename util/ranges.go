package util

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"

	range_parser "github.com/quantumsheep/range-parser"
)

type RangesFile struct {
	file            *os.File
	ranges          []*range_parser.Range
	i               int // current index in ranges
	offset          int // current offset in current range
	boundary        string
	headerGenerated bool // header already generated for current range
	header          string
	contentType     string
	fileSize        int64
}

func (rfb *RangesFile) Close() error {
	return rfb.file.Close()
}

func (rfb *RangesFile) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if rfb.i >= len(rfb.ranges) {
			return n, io.EOF
		}
		cr := rfb.ranges[rfb.i]
		// write part header
		if len(rfb.ranges) > 1 {
			if !rfb.headerGenerated {
				header := ""
				header += fmt.Sprintf("\r\n--%s\r\n", rfb.boundary)
				header += fmt.Sprintf("Content-Type: %s\r\n", rfb.contentType)
				header += fmt.Sprintf("Content-Range: bytes %d-%d/%d\r\n", cr.Start, cr.End, rfb.fileSize)
				header += "\r\n"
				rfb.header = header
				rfb.headerGenerated = true
			}
			if len(rfb.header) > 0 {
				readlen := min(len(p)-n, len(rfb.header))
				for i := 0; i < readlen; i++ {
					p[n+i] = rfb.header[i]
				}
				n += readlen
				rfb.header = rfb.header[readlen:]
				if n == len(p) {
					return n, nil
				}
			}
		}
		crl := int(cr.End - cr.Start + 1)
		if rfb.offset >= crl {
			return n, io.EOF
		}
		readlen := min(len(p)-n, crl-rfb.offset)
		rn, err := rfb.file.ReadAt(p[n:n+readlen], cr.Start+int64(rfb.offset))
		n += rn
		rfb.offset += rn
		if rfb.offset == crl {
			rfb.i++
			rfb.offset = 0
			rfb.headerGenerated = false
			rfb.header = ""
		}
		if err != nil || n == len(p) {
			return n, err
		}
	}
}

func (rfb *RangesFile) SetHeader(header http.Header) {
	if len(rfb.ranges) == 1 {
		header.Set("Content-Type", rfb.contentType)
		header.Set("Content-Length", fmt.Sprint(rfb.ranges[0].End-rfb.ranges[0].Start+1))
		header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rfb.ranges[0].Start, rfb.ranges[0].End, rfb.fileSize))
	} else {
		header.Set("Content-Type", fmt.Sprintf("multipart/byteranges; boundary=%s", rfb.boundary))
	}
}

// Reference: https://stackoverflow.com/questions/18315787/http-1-1-response-to-multiple-range .
// Return the body that will read from f according to ranges, which is parsed from http request "Range" header.
// The returned body is intended to be used in http response body.
// f will be closed then body is closed.
// Note http ranges is inclusive.
// E.g. "Range: bytes=0-499" : first 500 bytes.
func NewRangesFile(file *os.File, contentType string, fileSize int64, rangeHeader string) (*RangesFile, error) {
	ranges, err := range_parser.Parse(fileSize, rangeHeader)
	if err != nil {
		return nil, err
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	rfb := &RangesFile{file: file, ranges: ranges, boundary: randomBoundary(),
		contentType: contentType, fileSize: fileSize}
	return rfb, nil
}

func randomBoundary() string {
	var buf [30]byte
	_, err := io.ReadFull(rand.Reader, buf[:])
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", buf[:])
}
