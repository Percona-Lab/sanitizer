package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/Percona-Lab/sanitizer/internal/sanitize"
	"github.com/Percona-Lab/sanitizer/internal/sanitize/util"
	"github.com/alecthomas/kingpin"
	shellwords "github.com/mattn/go-shellwords"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
)

type cliOptions struct {
	BinDir              *string
	DataDir             *string
	NoSanitizeHostnames *bool
	NoSanitizeQueries   *bool
	NoDefaultCommads    *bool
	AdditionalCmds      *[]string
	AskMySQLPass        *bool
	MySQLHost           *string
	MySQLPort           *int
	MySQLUser           *string
	MySQLPass           *string
}

var (
	defaultCmds = []string{
		"pt-stalk --no-stalk --iterations=1 --sleep=3 --host=$mysql-host --dest=$data-dir --port=$mysql-port --user=$mysql-user --password=$mysql-pass",
	}
)

func main() {
	opts, err := processCliParams()
	if err != nil {
		log.Fatal(err)
	}

	log.SetLevel(log.DebugLevel)
	log.Infof("Data directory is %q", *opts.DataDir)

	if _, err = os.Stat(*opts.DataDir); os.IsNotExist(err) {
		log.Infof("Creating data directory: %s", *opts.DataDir)
		if err = os.Mkdir(*opts.DataDir, os.ModePerm); err != nil {
			log.Fatalf("Cannot create output dir %q: %s", *opts.DataDir, err)
		}
	}

	cmds, err := getCommandsToRun(defaultCmds, opts)

	// Run the commands
	if err = runCommands(cmds, *opts.DataDir); err != nil {
		log.Fatalf("Cannot run data collection commands: %s", err)
	}

	err = processFiles(*opts.DataDir, !*opts.NoSanitizeHostnames, !*opts.NoSanitizeQueries)
	if err != nil {
		log.Fatalf("Cannot sanitize files in %q: %s", *opts.DataDir, err)
	}

	tarfile := fmt.Sprintf(path.Join(*opts.DataDir, path.Base(*opts.DataDir)+".tar.gz"))
	log.Infof("Creating tar file %q", tarfile)
	if err = tarit(tarfile, *opts.DataDir); err != nil {
		log.Fatal(err)
	}

}

func processFiles(dataDir string, sanitizeHostnames, sanitizeQueries bool) error {
	files, err := ioutil.ReadDir(dataDir)
	if err != nil {
		return errors.Wrapf(err, "Cannot get the listing of %q", dataDir)
	}
	if len(files) == 0 {
		return errors.Errorf("There are no files to sanitize in %q", dataDir)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		inputFile := path.Join(dataDir, file.Name())
		fh, err := os.Open(inputFile)
		if err != nil {
			return errors.Wrapf(err, "Cannot open %q for reading", inputFile)
		}

		lines, err := util.ReadLinesFromFile(fh)
		if err != nil {
			return errors.Wrapf(err, "Cannot sanitize %q", inputFile)
		}
		sanitized := sanitize.Sanitize(lines, sanitizeHostnames, sanitizeQueries)

		outfile := path.Join(dataDir, file.Name())
		ofh, err := os.Create(outfile)
		if err != nil {
			return errors.Wrapf(err, "Cannot open %q for writing", outfile)
		}

		if err = util.WriteLinesToFile(ofh, sanitized); err != nil {
			return errors.Wrapf(err, "Cannot write sanitized file %q", outfile)
		}
	}
	return nil
}

func tarit(outfile string, srcPath string) error {
	files, err := ioutil.ReadDir(srcPath)
	if err != nil {
		return errors.Wrapf(err, "Cannot get the listing of %q", srcPath)
	}

	file, err := os.Create(outfile)
	if err != nil {
		return errors.Wrapf(err, "Cannot create tar file %q", outfile)
	}
	defer file.Close()

	gw := gzip.NewWriter(file)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	for _, file := range files {
		// Ignore tar.gz files from previous runs
		if strings.HasSuffix(file.Name(), ".tar.gz") {
			continue
		}
		if err := addFile(tw, srcPath, file); err != nil {
			return errors.Wrapf(err, "Cannot add %q to the tar file %q", file.Name(), outfile)
		}
	}

	return nil
}

func addFile(tw *tar.Writer, srcPath string, fileInfo os.FileInfo) error {
	file, err := os.Open(path.Join(srcPath, fileInfo.Name()))
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Stat(); err == nil {
		header, err := tar.FileInfoHeader(fileInfo, "")
		if err != nil {
			return errors.Wrapf(err, "Cannot create tar file header for %q", fileInfo.Name())
		}

		// Add the path since fileInfo.Name() only has the file name without the path
		header.Name = path.Join(path.Base(srcPath), fileInfo.Name())

		if err := tw.WriteHeader(header); err != nil {
			return errors.Wrapf(err, "Cannot write file header for %q into the tar file", fileInfo.Name())
		}

		if _, err := io.Copy(tw, file); err != nil {
			return errors.Wrapf(err, "Cannot write file %q to the tar file", fileInfo.Name())
		}
	}
	return nil
}

func getTempDir() (string, error) {
	user, err := user.Current()
	if err != nil {
		return "", errors.Wrap(err, "Cannot get current user information")
	}

	dir, err := ioutil.TempDir(user.HomeDir, "sanitize_")
	if err != nil {
		return "", errors.Wrap(err, "Cannot create temporary directory")
	}

	return dir, nil
}

func processCliParams() (*cliOptions, error) {
	u, err := user.Current()
	if err != nil {
		return nil, errors.Wrap(err, "Cannot get current user")
	}

	tmpdir := path.Join(u.HomeDir, fmt.Sprintf("data_collection_%s", time.Now().Format("2006-01-02_15_04_05")))
	err = os.Mkdir(tmpdir, os.ModePerm)

	if err != nil {
		return nil, errors.Wrap(err, "Cannot get a temporary directory for the output")
	}

	app := kingpin.New("collect", "Collect & Sanitize services data")
	options := &cliOptions{
		BinDir:              app.Flag("bin-dir", "Directory having the Percona Toolkit binaries (if they are not in PATH)").String(),
		DataDir:             app.Flag("data-dir", "Directory having the files to sanitize.").Default(tmpdir).String(),
		MySQLHost:           app.Flag("mysql-host", "MySQL host").String(),
		AskMySQLPass:        app.Flag("ask-pass", "Ask MySQL password").Bool(),
		MySQLPort:           app.Flag("mysql-port", "MySQL port").Int(),
		MySQLUser:           app.Flag("mysql-user", "MySQL user name").String(),
		MySQLPass:           app.Flag("mysql-pass", "MySQL password").String(),
		NoDefaultCommads:    app.Flag("no-default-commands", "Do not run the default commands").Bool(),
		NoSanitizeHostnames: app.Flag("no-sanitize-hostnames", "Don't sanitize host names").Bool(),
		NoSanitizeQueries:   app.Flag("no-sanitize-queries", "Don't replace queries by their fingerprints").Bool(),
		AdditionalCmds: app.Flag("extra-cmd",
			"Also run this command as part of the data collection. This parameter can be used more than once").Strings(),
	}
	app.Parse(os.Args[1:])

	if *options.BinDir != "" {
		os.Setenv("PATH", fmt.Sprintf("%s%s%s", *options.BinDir, string(os.PathListSeparator), os.Getenv("PATH")))
	}

	lp, err := exec.LookPath("pt-summary")
	if (err != nil || lp == "") && *options.BinDir == "" {
		return nil, errors.New("Cannot find Percona Toolkit binaries. Please run this tool again using --bin-dir parameter")
	}

	if *options.AskMySQLPass {
		passb, err := terminal.ReadPassword(0)
		if err != nil {
			return nil, errors.Wrap(err, "Cannot read MySQL password from the terminal")
		}
		*options.MySQLPass = string(passb)
	}

	return options, nil
}

func getCommandsToRun(defaultCmds []string, opts *cliOptions) ([]*exec.Cmd, error) {
	cmdList := []string{}
	cmds := []*exec.Cmd{}
	notAllowedCmdsRe := regexp.MustCompile("(rm|fdisk|rmdir)")

	if !*opts.NoDefaultCommads {
		cmdList = append(cmdList, defaultCmds...)
	}

	if *opts.AdditionalCmds != nil {
		cmdList = append(cmdList, *opts.AdditionalCmds...)
	}

	for _, cmdstr := range cmdList {
		cmdstr = strings.Replace(cmdstr, "$mysql-host", *opts.MySQLHost, -1)
		cmdstr = strings.Replace(cmdstr, "$mysql-port", fmt.Sprintf("%d", *opts.MySQLPort), -1)
		cmdstr = strings.Replace(cmdstr, "$mysql-user", *opts.MySQLUser, -1)
		cmdstr = strings.Replace(cmdstr, "$mysql-pass", *opts.MySQLPass, -1)
		cmdstr = strings.Replace(cmdstr, "$data-dir", *opts.DataDir, -1)

		args, err := shellwords.Parse(cmdstr)
		if err != nil {
			return nil, errors.Wrapf(err, "Cannot parse %q", cmdstr)
		}
		if found := notAllowedCmdsRe.FindAllString(args[0], -1); len(found) > 0 {
			continue
		}

		cmd := exec.Command(args[0], args[1:]...)
		cmds = append(cmds, cmd)
	}
	return cmds, nil
}

func runCommands(cmds []*exec.Cmd, dataDir string) error {
	for _, cmd := range cmds {
		logFile := fmt.Sprintf("%s_%s.out", path.Base(cmd.Args[0]), time.Now().Format("2006-01-02_15_04_05"))
		log.Infof("Creating output file %q", logFile)
		fh, err := os.Create(path.Join(dataDir, logFile))
		if err != nil {
			return errors.Wrapf(err, "Cannot create output file %s", logFile)
		}

		log.Infof("Executing %v", cmd.Args)
		stdoutStderr, err := cmd.CombinedOutput()
		if err != nil {
			fh.WriteString(fmt.Sprintf("There was a problem running %s with these arguments: %v.\n%s", cmd.Args[0], cmd.Args[1:], err))
			fh.Close()
			return errors.Wrapf(err, "There was a problem running %s with these arguments: %v.\n%s", cmd.Args[0], cmd.Args[1:], err)
		}
		fh.Write(stdoutStderr)
		fh.Close()
	}

	return nil
}
