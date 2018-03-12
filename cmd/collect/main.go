package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Percona-Lab/sanitizer/internal/sanitize"
	"github.com/Percona-Lab/sanitizer/internal/sanitize/util"
	"github.com/alecthomas/kingpin"
	"github.com/go-ini/ini"
	shellwords "github.com/mattn/go-shellwords"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
)

type cliOptions struct {
	BinDir              *string
	DataDir             *string // in case Percona Toolkit is not in the PATH
	ConfigFile          *string // .my.cnf file
	EncryptPassword     *string // if set, it will produce an encrypted .aes file
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
		"pt-stalk --no-stalk --iterations=2 --sleep=30 --host=$mysql-host --dest=$data-dir --port=$mysql-port --user=$mysql-user --password=$mysql-pass",
	}
)

func main() {
	opts, err := processCliParams()
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("blocksize: %v\n", aes.BlockSize)

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

	tarFile := fmt.Sprintf(path.Join(*opts.DataDir, path.Base(*opts.DataDir)+".tar.gz"))
	log.Infof("Creating tar file %q", tarFile)
	if err = tarit(tarFile, *opts.DataDir); err != nil {
		log.Fatal(err)
	}

	if *opts.EncryptPassword != "" {
		encryptedFile := fmt.Sprintf(path.Join(*opts.DataDir, path.Base(*opts.DataDir)+".aes"))
		log.Infof("Encrypting %q file into %q", tarFile, encryptedFile)
		encrypt(tarFile, encryptedFile, *opts.EncryptPassword)
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
		ConfigFile:          app.Flag("config-file", "Path to the config file.").Default("~/.my.cnf").String(),
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

		EncryptPassword: app.Flag("encrypt-password", "Encrypt the output file using this password."+
			" If ommited, the file won't be encrypted.").String(),
	}
	app.Parse(os.Args[1:])
	getParamsFromMyCnf(options)

	if *options.BinDir != "" {
		os.Setenv("PATH", fmt.Sprintf("%s%s%s", *options.BinDir, string(os.PathListSeparator), os.Getenv("PATH")))
	}

	lp, err := exec.LookPath("pt-summary")
	if (err != nil || lp == "") && *options.BinDir == "" && !*options.NoDefaultCommads {
		return nil, errors.New("Cannot find Percona Toolkit binaries. Please run this tool again using --bin-dir parameter")
	}

	if *options.AskMySQLPass {
		fmt.Printf("MySQL password for user %q:", *options.MySQLUser)
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

func encrypt(infile, outfile, pass string) {
	// We need to ensure the password has the correct size so, we cannot
	// use a string with a random lenght as a password.
	password := sha256.Sum256([]byte(pass))
	key := password[:]

	inFile, err := os.Open(infile)
	if err != nil {
		panic(err)
	}
	defer inFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// If the key is unique for each ciphertext, then it's ok to use a zero IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])

	outFile, err := os.OpenFile(outfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	writer := &cipher.StreamWriter{S: stream, W: outFile}
	// Copy the input file to the output file, encrypting as we go.
	if _, err := io.Copy(writer, inFile); err != nil {
		panic(err)
	}
}

func getParamsFromMyCnf(opts *cliOptions) error {
	if *opts.ConfigFile == "" {
		return nil
	}
	*opts.ConfigFile = expandHomeDir(*opts.ConfigFile)

	cfg, err := ini.Load(*opts.ConfigFile)
	if err != nil {
		return errors.Wrapf(err, "Cannot read config from %q", *opts.ConfigFile)
	}

	sec, err := cfg.GetSection("client")
	if err != nil {
		return errors.Wrapf(err, "Cannot read [client] section from %q", *opts.ConfigFile)
	}

	if val, err := sec.GetKey("user"); err == nil {
		*opts.MySQLUser = val.String()
	}
	if val, err := sec.GetKey("password"); err == nil {
		*opts.MySQLPass = val.String()
	}
	if val, err := sec.GetKey("host"); err == nil {
		*opts.MySQLHost = val.String()
	}
	if val, err := sec.GetKey("port"); err == nil {
		if *opts.MySQLPort, err = val.Int(); err != nil {
			return errors.Wrapf(err, "Cannot parse %q as the port number", val.String())
		}
	}

	return nil
}

func expandHomeDir(path string) string {
	usr, _ := user.Current()
	dir := usr.HomeDir

	if path[:2] == "~/" {
		path = filepath.Join(dir, path[2:])
	}
	return path
}
