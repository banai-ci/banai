package fsutils

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/banai-ci/banai/utils/shellutils"
)

func listFilesInFolder(folderPath string) []string {
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

//ZipFolder will zip a folder with all its files
func ZipFolder(zipFileName, sourcePath string) ([]string, error) {
	if sourcePath == "" {
		sourcePath = "."
	}
	filesToZip := listFilesInFolder(sourcePath)

	zFile, err := os.OpenFile(zipFileName, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, fmt.Errorf("Failed to create zip file: %s, %s", zipFileName, err)
	}
	defer zFile.Close()
	zwriter := zip.NewWriter(zFile)
	var srcFile *os.File
	for _, fileName := range filesToZip {
		zf, err := zwriter.Create(fileName)
		if err != nil {
			return nil, fmt.Errorf("Failed to generate zip file %s", err)
		}
		srcFile, err = os.Open(fileName)
		if err != nil {
			return nil, fmt.Errorf("Failed to generate zip file %s", err)
		}
		_, err = io.Copy(zf, srcFile)
		if err != nil {
			return nil, fmt.Errorf("Failed to zip file %s, %s", fileName, err)
		}
		srcFile.Close()

	}

	zwriter.Close()
	return filesToZip, nil
}

//Unzip zip file to target folder. If no target folder is given, will unzip to current folder
func Unzip(zipFileName, targetPath string) ([]string, error) {
	if targetPath == "" {
		targetPath = "."
	}

	zf, err := zip.OpenReader(zipFileName)
	if err != nil {
		return nil, fmt.Errorf("Failed to open zip file %s", zipFileName)
	}
	defer zf.Close()
	var destFilePath string
	var destFolder string
	var dstFile *os.File
	var zfc io.ReadCloser
	var extractedFiles = make([]string, 0)
	for _, zippedFile := range zf.File {
		destFilePath = filepath.Join(targetPath, zippedFile.Name)
		extractedFiles = append(extractedFiles, destFilePath)
		destFolder = filepath.Dir(destFilePath)
		err = os.MkdirAll(destFolder, 0755)

		if err != nil {
			return nil, fmt.Errorf("unzip Failed to create destination folder %s, %s", destFolder, err)
		}
		dstFile, err = os.OpenFile(destFilePath, os.O_CREATE|os.O_RDWR, 0644)
		if err != nil {
			return nil, fmt.Errorf("unzip Failed to create destination file %s, %s", destFilePath, err)
		}

		zfc, err = zippedFile.Open()
		if err != nil {
			return nil, fmt.Errorf("unzip Failed to open zipped file %s, %s", zippedFile.Name, err)
		}
		io.Copy(dstFile, zfc)
		zfc.Close()
		dstFile.Close()
	}

	return extractedFiles, nil
}

func copyDir(source, destination string) error {
	if destination == "" {
		destination = "."
	}
	srca, serr := filepath.Abs(source)
	desa, derr := filepath.Abs(destination)
	if serr != nil {
		return serr
	}
	if derr != nil {
		return derr
	}
	if srca == desa {
		return nil //No need to copy file to itself
	}

	dstat, e := os.Stat(destination)
	if os.IsNotExist(e) {
		os.MkdirAll(desa, 0755)
	} else {
		if !dstat.IsDir() {
			return fmt.Errorf("Cannot copy directory to file")
		}
	}

	res, e := shellutils.RunShellCommand(fmt.Sprintf("cp -r %s %s", srca, desa))
	if e != nil {
		return e
	}
	if res.Code != 0 {
		return fmt.Errorf("Exit copy directory with code %d", res.Code)
	}
	return nil
}

func copyFile(source, destination string) error {
	if destination == "" {
		destination = "."
	}
	srca, serr := filepath.Abs(source)
	desa, derr := filepath.Abs(destination)
	if serr != nil {
		return serr
	}
	if derr != nil {
		return derr
	}
	if srca == desa {
		return nil //nothing todo no need to copy the file to itself
	}
	res, e := shellutils.RunShellCommand(fmt.Sprintf("cp %s %s", srca, desa))
	if e != nil {
		return e
	}
	if res.Code != 0 {
		return fmt.Errorf("Exit copy file with code %d", res.Code)
	}
	return nil

}

//CopyfsItem copies source file or folder to a matching destination
func CopyfsItem(source, destination string) error {
	sourceStat, e := os.Stat(source)
	if e != nil {
		return e
	}

	if sourceStat.IsDir() {
		return copyDir(source, destination)
	}
	if sourceStat.Mode().IsRegular() {
		return copyFile(source, destination)
	}
	return fmt.Errorf("Cannot copy ", source)
}
