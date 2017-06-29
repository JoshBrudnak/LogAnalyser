package main

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/lib/pq"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	uMobileUses        = "create table if not exists uMobileUsers(id serial primary key, type text, ipAddress text, datetime text, requestType text, version text, protocol text, status int, time int)"
	uMobileIpEntry     = "create table if not exists uMobileIpEntries(id serial primary key, type text, ipAddress text, numberOfUses text)"
	uMobileData        = "create table if not exists uMobileLogData(id serial primary key, date text, iosLength int, androidLength int, duration text, iosTimeAverage int, androidTimeAverage int)"
	clearUses          = "drop table uMobileUsers"
	clearIpEntries     = "drop table uMobileIpEntries"
	uMobileInsert      = "INSERT INTO uMobileUsers(type, ipAddress, datetime, requesttype, version, protocol, status, time) VALUES($1, $2, $3, $4, $5, $6, $7, $8)"
	uMobileEntryInsert = "INSERT INTO uMobileIpEntries(type, ipAddress, numberofUses) VALUES($1, $2, $3)"
	logDataInsert      = "INSERT INTO uMobileLogData(date, iosLength, androidLength, duration, iosTimeAverage, androidTimeAverage) VALUES($1, $2, $3, $4, $5, $6)"
)

var db *sql.DB

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
	time        int
}

type entryCount struct {
	entry      string
	number     int
}

type logData struct {
	date     string
	duration string
	timeAvg  int
	length   int
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func query(sql string) {
	_, err := db.Query(sql)
	checkErr(err)
}

func insertInfoRow(sql string, finished chan bool, info userInfo) {
	timeString := strconv.Itoa(info.time)

	_, err := db.Exec(sql, info.mobileType, info.ipaddress, info.date, info.requestType, info.version, info.protocol, info.status, timeString)
	checkErr(err)
	finished <- true
}

func insertIpRow(sql string, finished chan bool, ipEntry entryCount, mType string) {
	_, err := db.Exec(sql, mType, ipEntry.entry, ipEntry.number)
	checkErr(err)
	finished <- true
}

func insertLogDataRow(sql string, androidInfo logData, iosInfo logData) {
	_, err := db.Exec(sql, iosInfo.date, iosInfo.length, androidInfo.length, iosInfo.duration, iosInfo.timeAvg, androidInfo.timeAvg)
	checkErr(err)
}

func grepLines(log *os.File, text string) []string {
	var foundLines []string
	scanner := bufio.NewScanner(log)
	for scanner.Scan() {
		if bytes.Contains(scanner.Bytes(), []byte(text)) {
			line := string(scanner.Bytes())
			foundLines = append(foundLines, line)
		}
	}
	log.Close()
	return foundLines
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

func analyseEntries(entries []userInfo, data chan logData) {
	var date []time.Time
	var ipEntry []string
	var statusEntry []string
	var timeAvg int
	var difference time.Duration
	entryLen := len(entries)
	infoFinished := make([]chan bool, entryLen)

	for i := range infoFinished {
		infoFinished[i] = make(chan bool)
	}

	for i := range entries {
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
		if entries[i].time != 0 {
			timeAvg += entries[i].time
		}
	}

	if len(entries) > 0 {
		timeAvg = timeAvg / len(entries)
	} else {
		timeAvg = 0
	}

	for i := range entries {
		go insertInfoRow(uMobileInsert, infoFinished[i], entries[i])
	}
	for i := range ipEntries {
		go insertIpRow(uMobileEntryInsert, ipFinished[i], ipEntries[i], entries[i].mobileType)
	}
	for i := range infoFinished {
		<-infoFinished[i]
	}
	for i := range ipFinished {
		<-ipFinished[i]
	}

	year, month, day := date[0].Date()
	sYear := strconv.Itoa(year)
	sMonth := month.String()
	sDay := strconv.Itoa(day)

	logDate := fmt.Sprintf("%s/%s/%s", sMonth, sDay, sYear)

	logStats := logData{logDate, difference.String(), timeAvg, entryLen}

	fmt.Print("Length: ")
	fmt.Println(entryLen)
	fmt.Print("Duration: ")
	fmt.Println(difference)
	fmt.Print("Time Average: ")
	fmt.Println(timeAvg)

	fmt.Println(len(data))
	fmt.Println(logStats)
	data <- logStats
}

func getEntries(lines []string, mobileType string, data chan logData) {
	entries := make([]userInfo, 0)
	logStats := make(chan logData)

	for i := 0; i < len(lines); i++ {
        var versions string
		finalLine := trimString(lines[i])
		lineParts := strings.Split(finalLine, " ")
		time := 0

		status, _ := strconv.Atoi(lineParts[6])
		dateArray := []string{lineParts[1], lineParts[2]}
		date := strings.Join(dateArray, " ")

		if len(lineParts) > 7 {
			time, _ = strconv.Atoi(lineParts[7])
		}

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

		entry := userInfo{mobileType, lineParts[0], date, lineParts[3], versions, lineParts[5], status, time}
		entries = append(entries, entry)
	}

	go analyseEntries(entries, logStats)
	finalLogStat := <-logStats
	fmt.Println("got stats")
	fmt.Println(finalLogStat)
	data <- finalLogStat
}

func getData(arg string, finished chan bool) {
	androidLogData := make(chan logData)
	iosLogData := make(chan logData)
	error := false

	iosLog, err := os.Open(arg)
	if err != nil {
		fmt.Printf("%s could not be found\n", arg)
		error = true
	}

	if !error {
		androidLog, _ := os.Open(arg)
		iosLines := grepLines(iosLog, "iOS")
		androidLines := grepLines(androidLog, "android")
		go getEntries(iosLines, "iOS", iosLogData)
		go getEntries(androidLines, "android", androidLogData)
		fmt.Println("will get data")
		iosData := <-iosLogData
		androidData := <-androidLogData
		fmt.Println("got data")

		insertLogDataRow(logDataInsert, androidData, iosData)
	}

	finished <- true
}

func main() {
	start := time.Now()
	var c config
	finished := make([]chan bool, len(os.Args)-1)
	for i := range finished {
		finished[i] = make(chan bool)
	}

	file, err := os.Open("database.json")
	checkErr(err)
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&c)
	checkErr(err)
	dbURL := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable", c.Username, c.Password, c.URL, c.Dbname)
	db, err = sql.Open("postgres", dbURL)
	db.SetMaxOpenConns(50)

	query(clearUses)
	query(clearIpEntries)
	query(uMobileUses)
	query(uMobileIpEntry)
	query(uMobileData)

	if err != nil {
		panic(err)
	} else {
		for i := 1; i < len(os.Args); i++ {
			go getData(os.Args[i], finished[i-1])
		}
		for i := range finished {
			<-finished[i]
			fmt.Println(i)
		}
	}
	elapsed := time.Since(start)
	fmt.Print("Program took ")
	fmt.Println(elapsed)
}
