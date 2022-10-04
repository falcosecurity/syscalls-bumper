package main

import (
	"bufio"
	"flag"
	log "github.com/sirupsen/logrus"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	libsRepoRoot *string
	dryRun       *bool
	overwrite    *bool
	verbose      *bool
)

type SyscallMap map[string]struct{}

func (s1 SyscallMap) Diff(s2 SyscallMap) SyscallMap {
	res := make(SyscallMap, 0)
	for key := range s1 {
		_, found := s2[key]
		if !found {
			res[key] = struct{}{}
		}
	}
	return res
}

func init() {
	userhome, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	libsRepoRoot = flag.String("repo-root", userhome+"/Work/libs", "falcosecurity/libs repo root")
	dryRun = flag.Bool("dry-run", false, "enable dry run mode")
	overwrite = flag.Bool("overwrite", false, "whether to overwrite existing files in libs repo")
	verbose = flag.Bool("verbose", false, "enable verbose logging")
}

func main() {
	// * open /usr/include/asm/unistd_64.h
	// * parse in a map[NR name]int
	// * open libs driver/syscall_table.c
	// * parse in another map[NR name]int supported syscalls
	// * diff between 2 maps
	// * for all the element in the resulting map, add an:
	// 	#ifdef __NR_new
	//		[__NR_new - SYSCALL_TABLE_ID0] = {.ppm_sc = PPM_SC_NEW},
	//	#endif
	// * Finally, do the same for PPM_SC entries in driver/ppm_events_public

	flag.Parse()

	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	log.Debugln("Loading system syscall map")
	systemMap := loadSystemMap()

	log.Debugln("Loading libs syscall map")
	libsMap := loadLibsMap()

	log.Debugln("Loading libs PPM_SC map")
	ppmScMap := loadLibsPpmScMap()

	log.Debugln("Diff system->libs syscall maps")
	diffMap := systemMap.Diff(libsMap)
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

	log.Debugln("Diff system->ppm sc maps")
	diffMap = systemMap.Diff(ppmScMap)
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
}

func loadSystemMap() SyscallMap {
	return loadSyscallMap("/usr/include/asm/unistd_64.h", func(line string) string {
		fields := strings.Fields(line)
		if len(fields) > 2 && strings.HasPrefix(fields[1], "__NR_") {
			return fields[1]
		}
		return ""
	})
}

func loadLibsMap() SyscallMap {
	return loadSyscallMap(*libsRepoRoot+"/driver/syscall_table.c", func(line string) string {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[__NR_") {
			return ""
		}
		if strings.HasPrefix(line, "[__NR_ia32_") {
			return ""
		}
		line = strings.TrimPrefix(line, "[")
		fields := strings.Fields(line)
		return fields[0]
	})
}

func loadLibsPpmScMap() SyscallMap {
	return loadSyscallMap(*libsRepoRoot+"/driver/ppm_events_public.h", func(line string) string {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "PPM_SC_X(") {
			return ""
		}

		// Skip enum ppm_syscall_code macro call
		if strings.HasPrefix(line, "PPM_SC_X(name, value)") {
			return ""
		}

		line = strings.TrimPrefix(line, "PPM_SC_X(")
		fields := strings.Split(line, ",")
		return strings.ToLower(fields[0])
	})
}

func loadSyscallMap(filepath string, filter func(string) string) SyscallMap {
	m := make(SyscallMap, 0)
	f, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()
		syscallNR := filter(line)
		if syscallNR != "" {
			m[strings.TrimPrefix(syscallNR, "__NR_")] = struct{}{}
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

	if *overwrite {
		// Step 3: no error -> move temp file to real file
		err = os.Rename(fW.Name(), fp)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Infoln("Output file: ", fW.Name())
	}
}
