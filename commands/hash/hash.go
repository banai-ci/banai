package docker

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/banai-ci/banai/infra"
	"github.com/sirupsen/logrus"
)

var banai *infra.Banai
var logger *logrus.Logger

func genericHashCalculator(hasher hash.Hash, src io.Reader) string {
	buf := make([]byte, 1024)
	io.CopyBuffer(hasher, src, buf)
	return hex.EncodeToString(hasher.Sum(nil))
}

func openFileForHash(fileName string) *os.File {
	fi, err := os.Stat(fileName)
	banai.PanicOnError(err)
	if !fi.Mode().IsRegular() {
		banai.PanicOnError(fmt.Errorf("Cannot calculate hash for %s", fileName))
	}
	f, err := os.Open(fileName)
	if err != nil {
		banai.PanicOnError(fmt.Errorf("Failed to open file %s, for reading: %e", fileName, err))
	}

	return f
}

//********************* MD5 *************************
func hashMD5Buf(bs []uint8) string {

	b := bytes.NewBuffer(bs)
	return genericHashCalculator(md5.New(), b)
}

func hashMD5Text(s string) string {
	b := bytes.NewBufferString(s)
	return genericHashCalculator(md5.New(), b)

}

func hashMD5File(fileName string) string {
	f := openFileForHash(fileName)
	defer f.Close()

	return genericHashCalculator(md5.New(), f)
}

//********************* SHA1 *************************
func sha1Buf(bs []uint8) string {

	b := bytes.NewBuffer(bs)
	return genericHashCalculator(sha1.New(), b)
}

func sha1Text(s string) string {
	b := bytes.NewBufferString(s)
	return genericHashCalculator(sha1.New(), b)

}

func sha1File(fileName string) string {
	f := openFileForHash(fileName)
	defer f.Close()

	return genericHashCalculator(sha1.New(), f)
}

//********************* SHA256 *************************
func sha256Buf(bs []uint8) string {

	b := bytes.NewBuffer(bs)
	return genericHashCalculator(sha256.New(), b)
}

func sha256Text(s string) string {
	b := bytes.NewBufferString(s)
	return genericHashCalculator(sha256.New(), b)

}

func sha256File(fileName string) string {
	f := openFileForHash(fileName)
	defer f.Close()

	return genericHashCalculator(sha256.New(), f)
}

//RegisterJSObjects registers Shell objects and functions
func RegisterJSObjects(b *infra.Banai) {
	banai = b
	logger = b.Logger

	banai.Jse.GlobalObject().Set("hashMd5File", hashMD5File)
	banai.Jse.GlobalObject().Set("hashMd5Text", hashMD5Text)
	banai.Jse.GlobalObject().Set("hashMd5Buffer", hashMD5Buf)
	banai.Jse.GlobalObject().Set("hashSha1File", sha1File)
	banai.Jse.GlobalObject().Set("hashSha1Text", sha1Text)
	banai.Jse.GlobalObject().Set("hashSha1Buffer", sha1Buf)
	banai.Jse.GlobalObject().Set("hashSha256File", sha256File)
	banai.Jse.GlobalObject().Set("hashSha256Text", sha256Text)
	banai.Jse.GlobalObject().Set("hashSha256Buffer", sha256Buf)
}
