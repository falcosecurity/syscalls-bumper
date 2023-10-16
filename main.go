// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

package main

import (
	"bufio"
	"flag"
	"github.com/blang/semver"
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

func UnionMaps(maps map[string]SyscallMap) SyscallMap {
	res := make(SyscallMap, 0)
	for _, s := range maps {
		for key, val := range s {
			if _, found := res[key]; !found {
				res[key] = val
			}
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

// key should be consistent with the one used by https://github.com/hrw/syscalls-table/tree/master/tables.
// Value should be the suffix used by libs/driver/syscall_compat_* headers.
var supportedArchs = map[string]string{
	"x86_64":  "x86_64",
	"arm64":   "aarch64",
	"s390x":   "s390x",
	"riscv64": "riscv64",
}

func main() {
	// * download system maps from https://github.com/hrw/syscalls-table
	// * parse in a map[syscallName]syscallNR
	// * find the union map (ie: the map with all syscalls from all supported archs tables)
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

	log.Debugf("Loading system syscall map for supported archs: %v\n", supportedArchs)
	linuxMap := make(map[string]SyscallMap)
	for tableArch, libsArch := range supportedArchs {
		// We download latest maps from  https://github.com/hrw/syscalls-table/tree/master/tables
		linuxMap[libsArch] = loadSystemMap(tableArch)
	}

	log.Debugln("Loading libs syscall map")
	libsMap := loadLibsMap()

	log.Debugln("Loading libs PPM_SC map")
	ppmScMap := loadLibsPpmScMap()

	log.Debugln("Finding union map for all supported archs")
	unionMap := UnionMaps(linuxMap)

	needSchemaBump := false

	log.Debugln("Diff unionMap->libs syscall maps")
	diffMap := unionMap.Diff(libsMap)
	if len(diffMap) > 0 {
		needSchemaBump = true
		if !*dryRun {
			log.Infoln("Updating libs syscall table")
			updateLibsSyscallTable(diffMap)
		} else {
			log.Infoln("Would have added to syscall table:", diffMap)
		}
	} else {
		log.Infoln("Nothing to do for libs syscall table")
	}

	log.Debugln("Diff unionMap->ppm sc maps")
	diffMap = unionMap.Diff(ppmScMap)
	if len(diffMap) > 0 {
		needSchemaBump = true
		if !*dryRun {
			log.Infoln("Updating libs PPM_SC enum")
			updateLibsPPMSc(diffMap)
			log.Infoln("Updating libscap/linux/scap_ppm_sc table")
			updateLibsEventsToScTable(diffMap)
		} else {
			log.Infoln("Would have added to PPM_SC enum:", diffMap)
		}
	} else {
		log.Infoln("Nothing to do for libs PPM_SC enum")
	}

	// Bump new compat files
	if !*dryRun {
		log.Infoln("Bumping new compat tables and ia32 to 64 x86 map table")
		bumpCompats(linuxMap)
		bumpIA32to64Map(linuxMap["x86_64"])
	} else {
		log.Infoln("Would have bumped compat tables", linuxMap)
	}

	// Bump patch schema version
	if !*dryRun {
		if needSchemaBump {
			log.Infoln("Bumping SCHEMA_VERSION patch")
			bumpPatchSchemaVersion()
		} else {
			log.Infoln("SCHEMA_VERSION patch bump not needed")
		}
	} else {
		log.Infoln("Would have bumped SCHEMA_VERSION patch")
	}

	if needSchemaBump {
		// Generate xml report
		generateReport(unionMap, linuxMap)
	} else {
		log.Infoln("No syscalls added. No need to generate updated report.")
	}
}

func generateReport(systemMap SyscallMap, linuxMap map[string]SyscallMap) {
	// Load syscalls mapped to events
	supportedMap := loadSyscallMap(*libsRepoRoot+"/driver/syscall_table.c", func(line string) (string, int64) {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[__NR_") {
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

	ensureFolderExists("libs/docs/")

	fW, err := os.Create("libs/docs/report.md")
	if err != nil {
		log.Fatal(err)
	}
	defer fW.Close()

	table := tablewriter.NewWriter(fW)
	table.SetHeader([]string{"Syscall", "Supported", "Architecture"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")

	sortedSlice := systemMap.SortKeys()

	data := make([]string, 3)
	for _, kv := range sortedSlice {
		data[0] = kv.Key
		if _, ok := supportedMap[kv.Key]; ok {
			data[1] = "🟢"
		} else {
			data[1] = "🟡"
		}

		var archs []string
		for arch := range linuxMap {
			if _, ok := linuxMap[arch][kv.Key]; ok {
				archs = append(archs, arch)
			}
		}
		data[2] = strings.Join(archs, ",")
		table.Append(data)
	}
	table.Render() // Send output

	checkOverwriteRepoFile(fW, *libsRepoRoot+"/docs/report.md")
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
	updateLibsMap(*libsRepoRoot+"/driver/syscall_table.c",
		func(lines *[]string, line string) bool {
			if line == "};" {
				for key := range syscallMap {
					ppmSc := "PPM_SC_" + strings.ToUpper(key)
					*lines = append(*lines, "#ifdef __NR_"+key)
					*lines = append(*lines, "\t[__NR_"+key+" - SYSCALL_TABLE_ID0] = {.ppm_sc = "+ppmSc+"},")
					*lines = append(*lines, "#endif")
				}
			}
			return false
		})
}

func updateLibsEventsToScTable(syscallMap SyscallMap) {
	updateLibsMap(*libsRepoRoot+"/userspace/libscap/linux/scap_ppm_sc.c",
		func(lines *[]string, line string) bool {
			if strings.Contains(line, "[PPME_GENERIC_") {
				newLine := strings.TrimSuffix(line, "-1},")
				for key := range syscallMap {
					ppmSc := "PPM_SC_" + strings.ToUpper(key)
					newLine += ppmSc + ", "
				}
				newLine += " -1},"
				*lines = append(*lines, newLine)
				return true
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

func ensureFolderExists(path string) {
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
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
	ensureFolderExists("libs/driver")

	fW, err := os.Create("libs/driver/" + filepath.Base(fp))
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

		fp := *libsRepoRoot + "/driver/syscall_compat_" + key + ".h"

		// Step 2: dump the new content to local (temp) file
		ensureFolderExists("libs/driver")

		fW, err := os.Create("libs/driver/" + filepath.Base(fp))
		if err != nil {
			log.Fatal(err)
		}

		writeBanner(fW)
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

func bumpPatchSchemaVersion() {
	updateLibsMap(*libsRepoRoot+"/driver/SCHEMA_VERSION",
		func(lines *[]string, line string) bool {
			v, err := semver.Parse(line)
			if err != nil {
				log.Fatal(err.Error())
			}
			v.Patch++
			*lines = append(*lines, v.String())
			return true // Filter out this line
		})
}

// Define here any translation between ia32 syscall nr and corresponding 64 bit compatible syscall.
var ia32TranslatorMap = map[int64]int64{
	/*
	 * 192 is mmap2 on ia32; since it is not defined on x86_64,
	 * and we manage it exactly like mmap, convert it to a mmap x86_64
	 */
	192: 9,
	/*
	 * stat64 on ia32 is not defined on x86_64; but x86_64 has a compatible `stat` event.
	 * Manage it just like a stat.
	 */
	195: 4,
	/*
	 * fstat64 on ia32 is not defined on x86_64; but x86_64 has a compatible `fstat` event.
	 * Manage it just like a stat.
	 */
	197: 5,
	/*
	 * lstat64 on ia32 is not defined on x86_64; but x86_64 has a compatible `lstat` event.
	 * Manage it just like a stat.
	 */
	196: 6,
	/*
	 * sendfile64 ia32 only; but it sends same event as sendfile.
	 * Forcefully convert it.
	 */
	239: 40,
	/*
	 * getgid32 ia32 only; but it sends same event as getgid.
	 * Forcefully convert it.
	 */
	200: 104,
	/*
	 * fcntl64 ia32 only; but it sends same event as fcntl.
	 * Forcefully convert it.
	 */
	221: 72,
	/*
	 * setuid32 ia32 only; but it sends same event as setuid.
	 * Forcefully convert it.
	 */
	213: 105,
	/*
	 * setresuid32 ia32 only; but it sends same event as setresuid.
	 * Forcefully convert it.
	 */
	208: 117,
	/*
	 * getegid32 ia32 only; but it sends same event as getegid.
	 * Forcefully convert it.
	 */
	202: 108,
	/*
	 * getresgid32 ia32 only; but it sends same event as getresgid.
	 * Forcefully convert it.
	 */
	211: 120,
	/*
	 * getresuid32 ia32 only; but it sends same event as getresuid.
	 * Forcefully convert it.
	 */
	209: 118,
	/*
	 * setresgid32 ia32 only; but it sends same event as setresgid.
	 * Forcefully convert it.
	 */
	210: 119,
	/*
	 * geteuid32 ia32 only; but it sends same event as geteuid.
	 * Forcefully convert it.
	 */
	201: 107,
	/*
	 * setgid32 ia32 only; but it sends same event as setgid.
	 * Forcefully convert it.
	 */
	214: 106,
	/*
	 * umount ia32 only; send a semi compatible umount2 instead.
	 * (only exit event is actually compatible, see https://github.com/falcosecurity/libs/blob/master/driver/event_table.c#L444
	 */
	22: 166,
}

func bumpIA32to64Map(x64Map SyscallMap) {
	fp := *libsRepoRoot + "/driver/syscall_ia32_64_map.c"

	x32Map := loadSyscallMap("https://raw.githubusercontent.com/hrw/syscalls-table/master/tables/syscalls-i386", func(line string) (string, int64) {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			syscallNr, _ := strconv.ParseInt(fields[1], 10, 64)
			return "__NR_" + fields[0], syscallNr
		}
		return "", -1
	})

	// Step 2: dump the new content to local (temp) file
	err := os.MkdirAll("driver", os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	fW, err := os.Create("driver/" + filepath.Base(fp))
	if err != nil {
		log.Fatal(err)
	}

	writeBanner(fW)

	_, _ = fW.WriteString("#include \"ppm_events_public.h\"\n")
	_, _ = fW.WriteString(`
/*
 * This table is used by drivers when receiving a 32bit syscall.
 * It is needed to convert a 32bit syscall (the array index) to a 64bit syscall value.
 * NOTE: some syscalls might be unavailable on x86_64; their value will be set to -1.
 * Some unavailable syscalls are identical to a compatible x86_64 syscall; in those cases,
 * we use the compatible x86_64 syscall, eg: mmap2 -> mmap.
 */
`)
	_, _ = fW.WriteString("const int g_ia32_64_map[SYSCALL_TABLE_SIZE] = {\n")
	for x32Name, x32Nr := range x32Map {
		x32NrStr := strconv.FormatInt(x32Nr, 10)
		if x64Nr, ok := x64Map[x32Name]; ok {
			x64NrStr := strconv.FormatInt(x64Nr, 10)
			_, _ = fW.WriteString("\t[" + x32NrStr + "] = " + x64NrStr + ",\n")
		} else {
			x64Nr, translated := ia32TranslatorMap[x32Nr]
			if translated {
				x64NrStr := strconv.FormatInt(x64Nr, 10)
				_, _ = fW.WriteString("\t[" + x32NrStr + "] = " + x64NrStr + ", // NOTE: syscall " + x32Name + " unmapped on x86_64, forcefully mapped to compatible syscall. See syscalls-bumper bumpIA32to64Map() call.\n")
			} else {
				_, _ = fW.WriteString("\t[" + x32NrStr + "] = -1, // ia32 only: " + x32Name + "\n")
			}
		}
	}
	_, _ = fW.WriteString("};\n")

	checkOverwriteRepoFile(fW, fp)
	_ = fW.Close()
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

func writeBanner(fW *os.File) {
	_, _ = fW.WriteString(
		`// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*

Copyright (C) 2023 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/

/*
 * This file was automatically created by syscalls-bumper (https://github.com/falcosecurity/syscalls-bumper).")
 * DO NOT EDIT THIS FILE MANUALLY.")
 */

`)
}
