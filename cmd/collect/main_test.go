package main

import (
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"testing"

	tu "github.com/Percona-Lab/mysql_random_data_load/testutils"
)

func TestTarIt(t *testing.T) {
	srcDir := "testdata"
	outfile, err := ioutil.TempFile(os.TempDir(), "")
	tu.IsNil(t, err)

	outFileName := outfile.Name() + ".tar.gz"

	fi, err := ioutil.ReadDir(srcDir)
	tu.IsNil(t, err)

	err = tarit(outFileName, srcDir, fi)
	tu.IsNil(t, err)

	// Run a real tar and diff to ensure a regular Linux tar can extract the files
	cmd := exec.Command("tar", "xvzf", outFileName, "-C", os.TempDir())
	err = cmd.Run()
	tu.IsNil(t, err)

	for _, f := range fi {
		tmpout := path.Join(os.TempDir(), "testdata", f.Name())
		cmd := exec.Command("diff", "testdata/"+f.Name(), tmpout)
		err := cmd.Run()
		tu.IsNil(t, err)

		os.Remove(tmpout)
	}

	os.Remove(outFileName)
	os.Remove(path.Join(os.TempDir(), "testdata"))
}
