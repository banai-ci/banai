package archive

import (
	"os"
	"path/filepath"

	"github.com/banai-ci/banai/infra"
	"github.com/banai-ci/banai/utils/fsutils"
	"github.com/sirupsen/logrus"
)

var banai *infra.Banai
var logger *logrus.Logger

func discoverFilesInFolder(folderPath string) []string {
	var files []string
	filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			if !info.IsDir() {
				files = append(files, path)
			}
			return nil
		}
		return err
	})

	return files
}

func archiveToZip(zipFileName string, sourcePath string) []string {

	zippedFiles, err := fsutils.ZipFolder(zipFileName, sourcePath)
	banai.PanicOnError(err)
	banai.Logger.Info(zippedFiles)
	return zippedFiles

}

func unarchiveFromZip(zipFileName, targetPath string) []string {

	fileList, err := fsutils.Unzip(zipFileName, targetPath)
	banai.PanicOnError(err)

	banai.Logger.Infof("Unzipped files %v", fileList)
	return fileList
}

//RegisterJSObjects register archive objects
func RegisterJSObjects(b *infra.Banai) {
	banai = b
	logger = b.Logger
	banai.Jse.GlobalObject().Set("arZip", archiveToZip)
	banai.Jse.GlobalObject().Set("arUnzip", unarchiveFromZip)
}
