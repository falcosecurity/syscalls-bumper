package main

import (
	"bufio"
	"flag"
	"github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var (
	libsRepoRoot *string
	dryRun       *bool
	overwrite    *bool
	verbose      *bool
)

type SyscallMap map[string]int64

type syscallKV struct {
	Key   string
	Value int64
}

func (s1 SyscallMap) SortValues() []syscallKV {
	var ss []syscallKV
	for k, v := range s1 {
		ss = append(ss, syscallKV{k, v})
	}

	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value < ss[j].Value
	})

	return ss
}

func (s1 SyscallMap) SortKeys() []syscallKV {
	var ss []syscallKV
	for k, v := range s1 {
		ss = append(ss, syscallKV{k, v})
	}

	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Key < ss[j].Key
	})

	return ss
}

func (s1 SyscallMap) Diff(s2 SyscallMap) SyscallMap {
	res := make(SyscallMap, 0)
	for key, val := range s1 {
		_, found := s2[key]
		if !found {
			res[key] = val
		}
	}
	return res
}

func init() {
	libsRepoRoot = flag.String("repo-root", "https://raw.githubusercontent.com/falcosecurity/libs/master", "falcosecurity/libs repo root (supports http too)")
	dryRun = flag.Bool("dry-run", false, "enable dry run mode")
	overwrite = flag.Bool("overwrite", false, "whether to overwrite existing files in libs repo if local")
	verbose = flag.Bool("verbose", false, "enable verbose logging")
}

func initOpts() {
	flag.Parse()

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	if *overwrite && strings.HasPrefix(*libsRepoRoot, "http") {
		log.Debugln("Force-disable overwrite when libs repo is remote")
		*overwrite = false
	}
}

func main() {
	// * download system maps from https://github.com/hrw/syscalls-table
	// * parse in a map[syscallName]syscallNR
	// * open libs driver/syscall_table.c
	// * parse in another map[syscallName]syscallNR supported syscalls (syscallNR is unused)
	// * diff between 2 maps
	// * for all the element in the resulting map, add an:
	// 	#ifdef __NR_new
	//		[__NR_new - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_NEW},
	//	#endif
	// * Do the same for PPM_SC entries in driver/ppm_events_public
	// * Finally, bump new compat tables
	initOpts()

	log.Debugln("Loading system syscall map for supported archs")
	systemMap := make(map[string]SyscallMap)
	// We download latest maps from  https://github.com/hrw/python-syscalls/blob/development/data/tables
	systemMap["x86_64"] = loadSystemMap("x86_64")
	systemMap["arm64"] = loadSystemMap("arm64")
	systemMap["s390x"] = loadSystemMap("s390x")

	log.Debugln("Loading libs syscall map")
	libsMap := loadLibsMap()

	log.Debugln("Loading libs PPM_SC map")
	ppmScMap := loadLibsPpmScMap()

	log.Debugln("Diff system(x86_64)->libs syscall maps")
	diffMap := systemMap["x86_64"].Diff(libsMap)
	if len(diffMap) > 0 {
		if !*dryRun {
			log.Infoln("Updating libs syscall table")
			updateLibsSyscallTable(diffMap)
		} else {
			log.Infoln("Would have added to syscall table:", diffMap)
		}
	} else {
		log.Infoln("Nothing to do for libs syscall table")
	}

	log.Debugln("Diff system(x86_64)->ppm sc maps")
	diffMap = systemMap["x86_64"].Diff(ppmScMap)
	if len(diffMap) > 0 {
		if !*dryRun {
			log.Infoln("Updating libs PPM_SC enum")
			updateLibsPPMSc(diffMap)
		} else {
			log.Infoln("Would have added to PPM_SC enum:", diffMap)
		}
	} else {
		log.Infoln("Nothing to do for libs PPM_SC enum")
	}

	// Bump new compat files
	if !*dryRun {
		log.Infoln("Bumping new compat tables")
		bumpCompats(systemMap)
	} else {
		log.Infoln("Would have bumped compat tables", systemMap)
	}

	// Generate xml report
	generateReport(systemMap["x86_64"])
}

func generateReport(systemMap SyscallMap) {
	// Load syscalls mapped to events
	supportedMap := loadSyscallMap(*libsRepoRoot+"/driver/syscall_table.c", func(line string) (string, int64) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[__NR_") {
			return "", -1
		}
		if strings.HasPrefix(line, "[__NR_ia32_") {
			return "", -1
		}
		// Drop lines without an event associated
		if strings.Index(line, "PPME") == -1 {
			return "", -1
		}
		line = strings.TrimPrefix(line, "[")
		fields := strings.Fields(line)
		return fields[0], -1 // no syscallnr available
	})

	fW, err := os.Create("driver/report.md")
	if err != nil {
		log.Fatal(err)
	}
	defer fW.Close()
	_, _ = fW.WriteString("# Supported Syscalls\n\n")
	_, _ = fW.WriteString("This table represents the syscalls supported by our drivers.\n\n")
	_, _ = fW.WriteString("🟢 means that the syscall is fully instrumented so its parameters are available to userspace.\n")
	_, _ = fW.WriteString("🟡 means that the syscall is not fully instrumented so the userspace is just notified when the syscall happens but no parameters are available.\n\n")
	table := tablewriter.NewWriter(fW)
	table.SetHeader([]string{"Syscall", "Supported"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")

	sortedSlice := systemMap.SortKeys()

	for _, kv := range sortedSlice {
		data := make([]string, 2)
		data[0] = kv.Key
		if _, ok := supportedMap[kv.Key]; ok {
			data[1] = "🟢"
		} else {
			data[1] = "🟡"
		}
		table.Append(data)
	}
	table.Render() // Send output

	checkOverwriteRepoFile(fW, *libsRepoRoot+"/driver/report.md")
}

func loadSystemMap(arch string) SyscallMap {
	return loadSyscallMap("https://raw.githubusercontent.com/hrw/syscalls-table/master/tables/syscalls-"+arch, func(line string) (string, int64) {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			syscallNr, _ := strconv.ParseInt(fields[1], 10, 64)
			return "__NR_" + fields[0], syscallNr
		}
		return "", -1
	})
}

func loadLibsMap() SyscallMap {
	return loadSyscallMap(*libsRepoRoot+"/driver/syscall_table.c", func(line string) (string, int64) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[__NR_") {
			return "", -1
		}
		if strings.HasPrefix(line, "[__NR_ia32_") {
			return "", -1
		}
		line = strings.TrimPrefix(line, "[")
		fields := strings.Fields(line)
		return fields[0], -1 // no syscallnr available
	})
}

func loadLibsPpmScMap() SyscallMap {
	return loadSyscallMap(*libsRepoRoot+"/driver/ppm_events_public.h", func(line string) (string, int64) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "PPM_SC_X(") {
			return "", -1
		}

		// Skip enum ppm_syscall_code macro call
		if strings.HasPrefix(line, "PPM_SC_X(name, value)") {
			return "", -1
		}

		line = strings.TrimPrefix(line, "PPM_SC_X(")
		fields := strings.Split(line, ",")
		return strings.ToLower(fields[0]), -1
	})
}

func downloadFile(filepath string, url string) (err error) {
	log.Debugln("Downloading from", url)
	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Writer the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func loadSyscallMap(filepath string, filter func(string) (string, int64)) SyscallMap {
	m := make(SyscallMap, 0)

	// Support http(s) urls
	if strings.HasPrefix(filepath, "http") {
		if err := downloadFile("/tmp/syscall.txt", filepath); err != nil {
			log.Fatal(err)
		}
		filepath = "/tmp/syscall.txt"
	}

	f, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()
		syscallName, syscallNR := filter(line)
		if syscallName != "" {
			m[strings.TrimPrefix(syscallName, "__NR_")] = syscallNR
		}
	}

	if err = scanner.Err(); err != nil {
		log.Fatal(err)
	}
	return m
}

func updateLibsSyscallTable(syscallMap SyscallMap) {
	isIA32 := false
	updateLibsMap(*libsRepoRoot+"/driver/syscall_table.c",
		func(lines *[]string, line string) bool {
			if line == "};" {
				for key := range syscallMap {
					ppmSc := "PPM_SC_" + strings.ToUpper(key)
					if isIA32 {
						*lines = append(*lines, "#ifdef __NR_ia32_"+key)
						*lines = append(*lines, "\t[__NR_ia32_"+key+" - SYSCALL_TABLE_ID0] = {.ppm_sc = "+ppmSc+"},")
					} else {
						*lines = append(*lines, "#ifdef __NR_"+key)
						*lines = append(*lines, "\t[__NR_"+key+" - SYSCALL_TABLE_ID0] = {.ppm_sc = "+ppmSc+"},")
					}
					*lines = append(*lines, "#endif")
				}
				isIA32 = true // next time print ia32 instead!
			}
			return false
		})
}

func updateLibsPPMSc(syscallMap SyscallMap) {
	updateLibsMap(*libsRepoRoot+"/driver/ppm_events_public.h",
		func(lines *[]string, line string) bool {
			// Basically, find all PPM_SC_X macro usages.
			// Then, find the last of the list, ie: the one without the ending "\"
			// because it is the last of the macro items
			if strings.HasPrefix(line, "\tPPM_SC_X(") &&
				!strings.HasSuffix(line, "\\") {

				// add the macro char "\" to end of line
				// then add all new macro values
				*lines = append(*lines, line+" \\")

				// Properly load last enum value
				vals := strings.Split(line, ",")
				idxStr := strings.TrimSpace(vals[1])
				idxStr = strings.TrimSuffix(idxStr, ")")
				lastVal, _ := strconv.ParseInt(idxStr, 10, 64)

				// Start adding new entries
				i := 0
				for key := range syscallMap {
					i++
					lastVal++
					ppmSc := strings.ToUpper(key)
					addedLine := "\tPPM_SC_X(" + ppmSc + ", " + strconv.FormatInt(lastVal, 10) + ")"
					// Eventually add the macro "\" char
					// for all new elements except last one
					if i < len(syscallMap) {
						addedLine += " \\"
					}
					*lines = append(*lines, addedLine)
				}
				return true
			}
			return false
		})
}

func updateLibsMap(fp string, filter func(*[]string, string) bool) {
	// Support http(s) urls
	if strings.HasPrefix(fp, "http") {
		if err := downloadFile("/tmp/"+filepath.Base(fp), fp); err != nil {
			log.Fatal(err)
		}
		fp = "/tmp/" + filepath.Base(fp)
	}

	f, err := os.Open(fp)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// Step 1: parse entire file eventually
	// storing in memory missing PPM_SC
	scanner := bufio.NewScanner(f)

	lines := make([]string, 0)

	for scanner.Scan() {
		line := scanner.Text()
		if !filter(&lines, line) {
			lines = append(lines, line)
		}
	}

	if err = scanner.Err(); err != nil {
		log.Fatal(err)
	}

	// Step 2: dump the new content to local (temp) file
	err = os.MkdirAll("driver", os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	fW, err := os.Create("driver/" + filepath.Base(fp))
	if err != nil {
		log.Fatal(err)
	}
	defer fW.Close()

	for _, line := range lines {
		_, err := fW.WriteString(line + "\n")
		if err != nil {
			log.Fatal(err)
		}
	}

	checkOverwriteRepoFile(fW, fp)
}

func bumpCompats(systemMap map[string]SyscallMap) {
	for key := range systemMap {
		// Step 1: sort map
		values := systemMap[key].SortValues()

		// We use "aarch64" in libs
		if key == "arm64" {
			key = "aarch64"
		}
		fp := *libsRepoRoot + "/driver/syscall_compat_" + key + ".h"

		// Step 2: dump the new content to local (temp) file
		err := os.MkdirAll("driver", os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
		fW, err := os.Create("driver/" + filepath.Base(fp))
		if err != nil {
			log.Fatal(err)
		}

		_, _ = fW.WriteString("#pragma once\n")
		for _, kv := range values {
			_, _ = fW.WriteString("#ifndef __NR_" + kv.Key + "\n")
			_, _ = fW.WriteString("#define __NR_" + kv.Key + " " + strconv.FormatInt(kv.Value, 10) + "\n")
			_, _ = fW.WriteString("#endif\n")
		}

		checkOverwriteRepoFile(fW, fp)
		_ = fW.Close()
	}
}

func checkOverwriteRepoFile(fW *os.File, fp string) {
	if *overwrite {
		// Step 3: no error -> move temp file to real file
		err := os.Rename(fW.Name(), fp)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Infoln("Output file: ", fW.Name())
	}
}
