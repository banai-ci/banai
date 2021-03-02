package fs

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/banai-ci/banai/infra"
	"github.com/banai-ci/banai/utils/fsutils"
	"github.com/banai-ci/banai/utils/shellutils"
	"github.com/dop251/goja"
)

var banai *infra.Banai

func readFileContent(fileName string) ([]byte, error) {
	info, err := os.Stat(fileName)
	if err != nil {
		banai.Logger.Panicf("Error reading %s, %s", fileName, err)
	}
	if info.IsDir() {
		banai.Logger.Panicf("file %s is a directory", fileName)
	}
	return ioutil.ReadFile(fileName)

}

func readFile(fileName string) goja.Value {

	ba, err := readFileContent(fileName)
	banai.PanicOnError(err)

	var v goja.Value
	if !utf8.Valid(ba) {
		v = banai.Jse.ToValue(ba)
		if err != nil {
			banai.Logger.Panic(err)
		}
	} else {
		v = banai.Jse.ToValue(string(ba))
		if err != nil {
			banai.Logger.Panic(err)
		}
	}

	return v
}

func writeFile(fileName string, v goja.Value) {

	paramVal := v.Export()

	var asByteArray []byte
	var ok bool
	var s string
	asByteArray, ok = paramVal.([]byte)
	if !ok {
		s, ok = paramVal.(string)
		if ok {
			asByteArray = []byte(s)
		} else {
			banai.PanicOnError(errors.New("Cannot save this type of data. Can be string or ByteArray"))
		}
	}

	err := ioutil.WriteFile(fileName, asByteArray, 0644)
	if err != nil {
		banai.PanicOnError(fmt.Errorf("Error writing file %s: %s", fileName, err))
	}
}

func createDir(dirName string) {
	s, err := os.Stat(dirName)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(dirName, 0755); err != nil {
			banai.PanicOnError(fmt.Errorf("Failed to create dir %s", err))
		}
	} else {
		if !s.IsDir() {
			banai.PanicOnError(fmt.Errorf("Already have file by that name"))
		}
	}
}

func fsRemoveDir(itemName string) {
	banai.Logger.Info("Deleting all under ", itemName)
	err := os.RemoveAll(itemName)
	if err != nil {
		if !os.IsNotExist(err) {
			banai.PanicOnError(fmt.Errorf("Failed to delete %s, %s", itemName, err))
		}
	}

}

func fsRemove(itemName string) {

	err := os.Remove(itemName)
	if err != nil {
		if !os.IsNotExist(err) {
			banai.PanicOnError(fmt.Errorf("Failed to delete %s, %s", itemName, err))
		}
	}
}

func copyFiles(sourceFileName, destinationFileName string) error {
	fileState, err := os.Stat(sourceFileName)
	if err != nil {
		return err
	}
	if !fileState.Mode().IsRegular() {
		return fmt.Errorf("Invalid source file")
	}
	fileState, err = os.Stat(destinationFileName)
	if err == nil {
		if fileState.IsDir() {
			destinationFileName = filepath.Join(destinationFileName, sourceFileName)
		}
	}

	banai.Logger.Infof("Copy %s -> %s", sourceFileName, destinationFileName)

	source, err := os.Open(sourceFileName)
	if err != nil {
		return fmt.Errorf("Failed to open source file %s for copy %s", sourceFileName, err)
	}
	defer source.Close()

	destination, err := os.OpenFile(destinationFileName, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("Failed to open destination file %s for copy %s", destinationFileName, err)
	}
	defer destination.Close()

	copyBuf := make([]byte, 4096)
	_, err = io.CopyBuffer(destination, source, copyBuf)
	return err
}

func fsCopy(sourceFileName, destinationFileName string) {
	err := fsutils.CopyfsItem(sourceFileName, destinationFileName)
	if err != nil {
		banai.PanicOnError(fmt.Errorf("Failed to copy files ", err))
	}

}

func fsMove(sourceFileName, destinationFileName string) {

	result, err := shellutils.RunShellCommand(fmt.Sprintf("mv %s %s", sourceFileName, destinationFileName))
	if err != nil {
		banai.PanicOnError(fmt.Errorf("Failed to move ", err))
	}
	if result.Code != 0 {
		banai.PanicOnError(fmt.Errorf("Move exit code ", result.Code))
	}

}

type splitPathNameParts struct {
	Folder string `json:"folder,omitempty"`
	File   string `json:"file,omitempty"`
	Title  string `json:"title,omitempty"`
	Ext    string `json:"ext,omitempty"`
}

func splitPathNameComponents(pathName string) splitPathNameParts {
	dirName, fileName := filepath.Split(pathName)
	extName := filepath.Ext(fileName)

	ret := splitPathNameParts{
		Folder: filepath.Clean(dirName),
		File:   fileName,
		Ext:    extName,
	}
	if ret.Ext != "" {
		ret.Title = ret.File[:len(ret.File)-len(ret.Ext)]
	} else {
		ret.Title = ret.File
	}

	return ret
}

func joinPathParts(parts ...string) string {
	s := filepath.Join(parts...)
	return s
}

func listAllSubitemsInDir(root string, elementType ...string) []string {
	var rootFolder = "."
	var itemType = ""

	if strings.TrimSpace(root) != "" {
		rootFolder = root
	}

	if elementType != nil && len(elementType) > 0 {
		switch elementType[0] {
		case "f":
			itemType = "f"
		case "d":
			itemType = "d"
		default:
			itemType = ""
		}
	}

	ret := make([]string, 0)
	err := filepath.Walk(rootFolder, func(path string, info os.FileInfo, err error) error {
		if err == nil {
			switch itemType {
			case "f":
				if info.Mode().IsRegular() {
					ret = append(ret, path)
				}
			case "d":
				if info.IsDir() {
					if path != rootFolder {
						ret = append(ret, path)
					}

				}
			default:
				ret = append(ret, path)
			}

		}
		return err
	})
	banai.PanicOnError(err)
	return ret
}

func absoluteFolder(folder string) string {
	folder = strings.TrimSpace(folder)
	if folder != "" {
		folder = "."
	}

	s, err := filepath.Abs(folder)
	banai.PanicOnError(err)

	return s
}

func currentPath() string {
	s, err := os.Getwd()
	banai.PanicOnError(err)
	return s
}

func changeDir(dir string) {
	banai.PanicOnError(os.Chdir(dir))
}

type fileInfo struct {
	IsDir        bool      `json:"isDir,omitempty"`
	IsFile       bool      `json:"isFile,omitempty"`
	Size         int64     `json:"size,omitempty"`
	LastModified time.Time `json:"lastModified,omitempty"`
}

func fsItemInfo(itemPath string) fileInfo {
	fs, err := os.Stat(itemPath)
	banai.PanicOnError(err)
	ret := fileInfo{
		IsDir:        fs.IsDir(),
		IsFile:       fs.Mode().IsRegular(),
		Size:         fs.Size(),
		LastModified: fs.ModTime(),
	}

	return ret
}

//RegisterJSObjects registers fs objects and functions
func RegisterJSObjects(b *infra.Banai) {
	banai = b

	banai.Jse.GlobalObject().Set("fsRead", readFile)
	banai.Jse.GlobalObject().Set("fsWrite", writeFile)
	banai.Jse.GlobalObject().Set("fsCreateDir", createDir)
	banai.Jse.GlobalObject().Set("fsRemoveDir", fsRemoveDir)
	banai.Jse.GlobalObject().Set("fsRemove", fsRemove)
	banai.Jse.GlobalObject().Set("fsCopy", fsCopy)
	banai.Jse.GlobalObject().Set("fsMove", fsMove)
	banai.Jse.GlobalObject().Set("fsSplit", splitPathNameComponents)
	banai.Jse.GlobalObject().Set("fsJoin", joinPathParts)
	banai.Jse.GlobalObject().Set("fsList", listAllSubitemsInDir)
	banai.Jse.GlobalObject().Set("fsAbs", absoluteFolder)
	banai.Jse.GlobalObject().Set("fsPwd", currentPath)
	banai.Jse.GlobalObject().Set("fsChdir", changeDir)
	banai.Jse.GlobalObject().Set("fsItemInfo", fsItemInfo)

}
