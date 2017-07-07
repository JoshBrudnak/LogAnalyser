package main

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

const (
	uMobileUses        = "create table if not exists uMobileUsers(id serial primary key, type text, ipAddress text, datetime text, requestType text, version text, protocol text, status int, bytes int)"
	uMobileIpEntry     = "create table if not exists uMobileIpEntries(id serial primary key, type text, ipAddress text, numberOfUses text)"
	uMobileData        = "create table if not exists uMobileLogData(id serial primary key, date text, startTime time, endTime time, iosLength int, androidLength int, duration text, iosBytesAverage int, androidBytesAverage int)"
	uMobileInsert      = "INSERT INTO uMobileUsers(type, ipAddress, datetime, requesttype, version, protocol, status, bytes) VALUES($1, $2, $3, $4, $5, $6, $7, $8)"
	uMobileEntryInsert = "INSERT INTO uMobileIpEntries(type, ipAddress, numberofUses) VALUES($1, $2, $3)"
	logDataInsert      = "INSERT INTO uMobileLogData(date, startTime, endTime, iosLength, androidLength, duration, iosBytesAverage, androidBytesAverage) VALUES($1, $2, $3, $4, $5, $6, $7, $8)"
)

var db *sql.DB
var logOnly bool

type config struct {
	URL      string
	Username string
	Password string
	Dbname   string
}

type userInfo struct {
	mobileType  string
	ipaddress   string
	date        string
	requestType string
	version     string
	protocol    string
	status      int
	bytes       int
}

type entryCount struct {
	entry  string
	number int
}

type logData struct {
	date      string
	startTime string
	endTime   string
	duration  string
	dataAvg   int
	length    int
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func logIfErr(err error) {
	if err != nil {
		log.Println(err)
	}
}

func query(sql string) {
	_, err := db.Query(sql)
	checkErr(err)
}

func getInstructions() {
	dir := "Log Analyser Manual\n\nSYNOPSIS\n\tlogAnalyser [flags] [file names/path]\nDESCRIPTION\n\t-h\tDisplay the help menu.\n\t-a\tAnalyse all text files in the current directory.\n\t-l\tOnly save overall log statistics. User and ip entry data will not be saved"
	fmt.Println(dir)
}

func insertInfoRow(finished chan bool, info userInfo) {
	bytesString := strconv.Itoa(info.bytes)
	ip := []byte(info.ipaddress)
	ipHash, _ := bcrypt.GenerateFromPassword(ip, bcrypt.MinCost)
	_, err := db.Exec(uMobileInsert, info.mobileType, ipHash, info.date, info.requestType, info.version, info.protocol, info.status, bytesString)
	logIfErr(err)
	finished <- true
}

func insertIpRow(finished chan bool, ipEntry entryCount, mType string) {
	ip := []byte(ipEntry.entry)
	ipHash, _ := bcrypt.GenerateFromPassword(ip, bcrypt.MinCost)
	_, err := db.Exec(uMobileEntryInsert, mType, ipHash, ipEntry.number)
	logIfErr(err)
	finished <- true
}

func insertLogDataRow(androidInfo logData, iosInfo logData) {
	_, err := db.Exec(logDataInsert, iosInfo.date, iosInfo.startTime, iosInfo.endTime, iosInfo.length, androidInfo.length, iosInfo.duration, iosInfo.dataAvg, androidInfo.dataAvg)
	logIfErr(err)
}

func getTime(dateTime string) string {
	time, _ := time.Parse("02/Jan/2006:15:04:05 -0700", dateTime)
	hour, min, sec := time.Clock()
	sHour := strconv.Itoa(hour)
	sMin := strconv.Itoa(min)
	sSec := strconv.Itoa(sec)
	s := []string{sHour, ":", sMin, ":", sSec}
	clock := strings.Join(s, "")

	return clock
}

func grepLines(log *os.File) ([]string, []string) {
	var iosLines, androidLines []string
	scanner := bufio.NewScanner(log)
	for scanner.Scan() {
		if bytes.Contains(scanner.Bytes(), []byte("android")) {
			line := string(scanner.Bytes())
			androidLines = append(androidLines, line)
		} else if bytes.Contains(scanner.Bytes(), []byte("iOS")) {
			line := string(scanner.Bytes())
			iosLines = append(iosLines, line)
		}
	}
	log.Close()
	return androidLines, iosLines
}

func trimString(text string) string {
	var replacer = strings.NewReplacer("[", "", "]", "", "- ", "", "\"", "")
	reg, _ := regexp.Compile(`^ +| +$|(  )+`)
	trimmedLine := replacer.Replace(text)
	newText := reg.ReplaceAllString(trimmedLine, "")

	return newText
}

func getEntryCount(entries []string) []entryCount {
	var entryMembers []entryCount

	for i := range entries {
		found := false
		index := 0
		for j := range entryMembers {
			if entryMembers[j].entry == entries[i] {
				found = true
				index = j
			}
		}
		if !found {
			ipentry := entryCount{entries[i], 1}
			entryMembers = append(entryMembers, ipentry)
		} else {
			ipNum := entryMembers[index].number + 1
			entryMembers[index].number = ipNum
		}
	}
	return entryMembers
}

func analyseEntries(entries []userInfo) logData {
	var date []time.Time
	var ipEntry, statusEntry []string
	var dataAvg int
	var difference time.Duration
	entryLen := len(entries)
	infoFinished := make([]chan bool, entryLen)
	count := 0

	for i := range entries {
		infoFinished[i] = make(chan bool)
		time, _ := time.Parse("02/Jan/2006:15:04:05 -0700", entries[i].date)
		date = append(date, time)
		ipEntry = append(ipEntry, entries[i].ipaddress)
		status := strconv.Itoa(entries[i].status)
		statusEntry = append(statusEntry, status)
	}

	ipEntries := getEntryCount(ipEntry)
	ipFinished := make([]chan bool, len(ipEntries))
	for i := range ipFinished {
		ipFinished[i] = make(chan bool)
	}
	if len(date) > 0 {
		difference = date[len(date)-1].Sub(date[0])
	}
	for i := range entries {
		if entries[i].bytes != 0 {
			dataAvg += entries[i].bytes
			count++
		}
	}
	if len(entries) > 0 {
		dataAvg = dataAvg / count
	} else {
		dataAvg = 0
	}
	if !logOnly {
		for i := range entries {
			go insertInfoRow(infoFinished[i], entries[i])
		}
		for i := range ipEntries {
			go insertIpRow(ipFinished[i], ipEntries[i], entries[i].mobileType)
		}
		for i := range infoFinished {
			<-infoFinished[i]
		}
		for i := range ipFinished {
			<-ipFinished[i]
		}
	}

	//Set up log data struct
	startClock := getTime(entries[0].date)
	endClock := getTime(entries[len(entries)-1].date)
	year, month, day := date[0].Date()
	sYear := strconv.Itoa(year)
	sMonth := month.String()
	sDay := strconv.Itoa(day)
	logDate := fmt.Sprintf("%s/%s/%s", sMonth, sDay, sYear)
	logStats := logData{logDate, startClock, endClock, difference.String(), dataAvg, entryLen}

	return logStats
}

func getEntries(lines []string, mobileType string, data chan logData) {
	entries := make([]userInfo, 0)

	for i := 0; i < len(lines); i++ {
		var versions string
		finalLine := trimString(lines[i])
		lineParts := strings.Split(finalLine, " ")
		if len(lineParts) > 7 {
			status, _ := strconv.Atoi(lineParts[6])
			dateArray := []string{lineParts[1], lineParts[2]}
			date := strings.Join(dateArray, " ")
			bytes, _ := strconv.Atoi(lineParts[7])

			// find version number
			urlParts := strings.Split(lineParts[4], "/")
			for j := range urlParts {
				versionParts := strings.Split(urlParts[j], "")
				if len(versionParts) > 0 {
					_, err := strconv.Atoi(versionParts[0])
					if err == nil {
						versions = urlParts[j]
						break
					}
				}
			}
			entry := userInfo{mobileType, lineParts[0], date, lineParts[3], versions, lineParts[5], status, bytes}
			entries = append(entries, entry)
		} else {
			log.Println("Index out of range log entry is not valid")
		}
	}

	logStats := analyseEntries(entries)
	data <- logStats
}

func getData(arg string, finished chan bool) {
	iosLogData := make(chan logData)
	androidLogData := make(chan logData)
	logFile, err := os.Open(arg)
	if err != nil {
		fmt.Printf("%s could not be found\n", arg)
	} else {
		androidLines, iosLines := grepLines(logFile)
		go getEntries(iosLines, "iOS", iosLogData)
		go getEntries(androidLines, "android", androidLogData)
		iosData := <-iosLogData
		androidData := <-androidLogData
		insertLogDataRow(androidData, iosData)
	}
	log.Printf("Finished analysing %s", arg)
	finished <- true
}

func init() {
	var c config
	file, err := os.Open("database.json")
	checkErr(err)
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&c)
	checkErr(err)
	dbURL := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", c.Username, c.Password, c.URL, c.Dbname)
	db, err = sql.Open("postgres", dbURL)
	checkErr(err)
	db.SetMaxOpenConns(80)

	f, err := os.OpenFile("uMobileLogAnalysis.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	log.SetOutput(f)
}

func main() {
	var help, all bool
	flag.BoolVar(&help, "h", false, "help menu")
	flag.BoolVar(&all, "a", false, "analyse all logs")
	flag.BoolVar(&logOnly, "l", false, "only save overall log data")
	flag.Parse()
	fileArgs := flag.Args()

	if help {
		getInstructions()
		return
	}
	if all {
		files, _ := ioutil.ReadDir("./")
		for _, f := range files {
			name := f.Name()
			if strings.Contains(name, "localhost_access_log") {
				fileArgs = append(fileArgs, name)
			}
		}
	}
	finished := make([]chan bool, len(fileArgs))
	for i := range finished {
		finished[i] = make(chan bool)
	}
	query(uMobileUses)
	query(uMobileIpEntry)
	query(uMobileData)

	for i := 0; i < len(fileArgs); i++ {
		go getData(fileArgs[i], finished[i])
	}
	for i := range finished {
		<-finished[i]
	}
}
