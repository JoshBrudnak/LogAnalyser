package main

import (
  "fmt"
  "os"
  "bufio"
  "bytes"
  "strings"
  "strconv"
  "regexp"
  "time"
  "encoding/json"
  "database/sql"
  _"github.com/lib/pq"
)

const (
	uMobileUses = "create table if not exists uMobileUsers(id serial primary key, type text, ipAddress text, datetime text, requestType text, version text, protocol text, status int, time int)"
    uMobileIpEntry = "create table if not exists uMobileIpEntries(id serial primary key, type text, ipAddress text, numberOfUses text)"
    uMobileData = "create table if not exists uMobileLogData(id serial primary key, date text, iosLength int, androidLength int, duration text, iosTimeAverage int, androidTimeAverege int)"
    clearUses = "drop table uMobileUsers"
    clearIpEntries = "drop table uMobileIpEntries"
    uMobileInsert = "INSERT INTO uMobileUsers(type, ipAddress, datetime, requesttype, version, protocol, status, time) VALUES($1, $2, $3, $4, $5, $6, $7, $8)"
    uMobileEntryInsert = "INSERT INTO uMobileIpEntries(type, ipAddress, numberofUses) VALUES($1, $2, $3)"
    logDataInsert = "INSERT INTO uMobileLogData(date, iosLength, androidLength, duration, iosTimeAverage, androidTimeAverage) VALUES($1, $2, $3, $4, $5, $6)"
)

var db *sql.DB

type config struct {
	URL      string
	Username string
	Password string
	Dbname   string
}

type userInfo struct {
  ipaddress string
  date string
  requestType string
  url string
  protocol string
  status int
  time int
}

type entryCount struct {
  entry string
  number int
}

type logData struct {
  date string
  duration string
  timeAvg int
  length int
}

func (info *userInfo) setIp(ip string) {
  info.ipaddress = ip
}

func (info *userInfo) setDate(date string) {
  info.date = date
}

func (info *userInfo) setRequestType(reqType string) {
  info.requestType = reqType
}

func (info *userInfo) setUrl(url string) {
  info.url = url
}

func (info *userInfo) setProtocol(proto string) {
  info.protocol = proto
}

func (info *userInfo) setStatus(status int) {
  info.status = status
}

func (info *userInfo) setTime(time int) {
  info.time = time
}

func (count *entryCount) setEntry(entry string) {
  count.entry = entry
}

func (count *entryCount) setNumber(number int) {
  count.number = number
}

func (log *logData) setDate(date string) {
  log.date = date
}

func (log *logData) setDuration(dur string) {
  log.duration = dur
}

func (log *logData) setTime(time int) {
  log.timeAvg = time
}

func (log *logData) setLength(length int) {
  log.length = length
}

func checkErr(err error) {
  if err != nil {
    panic(err)
  }
}

func query(sql string) {
  _,err := db.Query(sql)
  checkErr(err)
}

func insertInfoRow(sql string, finished chan bool, info userInfo, eType string, version string) {
  timeString := strconv.Itoa(info.time)

  _,err := db.Exec(sql, eType, info.ipaddress, info.date, info.requestType, version, info.protocol, info.status, timeString)
  checkErr(err)
  finished <- true
}

func insertIpRow(sql string, finished chan bool, ipEntry entryCount, eType string) {
  _,err := db.Exec(sql, eType, ipEntry.entry, ipEntry.number)
  checkErr(err)
  finished <- true
}

func insertLogDataRow(sql string, androidInfo logData, iosInfo logData) {
  _,err := db.Exec(sql, iosInfo.date, iosInfo.length, androidInfo.length, iosInfo.duration, iosInfo.timeAvg, androidInfo.timeAvg)
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
  reg,_ := regexp.Compile(`^ +| +$|(  )+`)
  trimmedLine := replacer.Replace(text)
  newText := reg.ReplaceAllString(trimmedLine, "")

  return newText
}

func getEntryCount(entries []string) []entryCount {
  var entryMembers []entryCount
  var ipentry entryCount

  for i := range entries {
    found := false
    index := 0
    for j := range entryMembers {
      if(entryMembers[j].entry == entries[i]){
        found = true
        index = j
      }
    }

    if(!found){
      ipentry.setEntry(entries[i])
      ipentry.setNumber(1)
      entryMembers = append(entryMembers, ipentry)
    } else {
      entryMembers[index].setNumber(entryMembers[index].number + 1)
    }
  }
  return entryMembers
}

func analyseEntries(entries []userInfo, entryType string, data chan logData) {
  length := len(entries)
  var date []time.Time
  var ipEntry []string
  var statusEntry []string
  var timeAvg int
  var versions []string
  var difference time.Duration
  var logStats logData
  entryLen := len(entries)
  infoFinished := make([]chan bool, entryLen)
  for i := range infoFinished {
    infoFinished[i] = make(chan bool)
  }

  for i := range entries {
    time,_ := time.Parse("02/Jan/2006:15:04:05 -0700", entries[i].date)
    date = append(date, time)
    ipEntry = append(ipEntry, entries[i].ipaddress)
    status := strconv.Itoa(entries[i].status)
    statusEntry = append(statusEntry, status)
  }

  for i := range entries {
    urlParts := strings.Split(entries[i].url, "/")
    for j := range urlParts {
      versionParts := strings.Split(urlParts[j], "")
      if(len(versionParts) > 0) {
        _,err := strconv.ParseFloat(versionParts[0], 64)
        if(err == nil) {
          versions = append(versions, urlParts[j])
          break
        }
      }
    }
  }

  ipEntries := getEntryCount(ipEntry)
  //statusEntries := getEntryCount(statusEntry)
  ipFinished := make([]chan bool, len(ipEntries))
  for i := range ipFinished {
    ipFinished[i] = make(chan bool)
  }

  if len(date) > 0 {
    difference = date[len(date) - 1].Sub(date[0])
  }

  for i := range entries {
    if(entries[i].time != 0) {
      timeAvg += entries[i].time
    }
  }

  if len(entries) > 0 {
    timeAvg = timeAvg / len(entries)
  } else {
    timeAvg = 0
  }

  for i := range entries {
    go insertInfoRow(uMobileInsert, infoFinished[i], entries[i], entryType, versions[i])
  }
  for i := range ipEntries {
    go insertIpRow(uMobileEntryInsert, ipFinished[i], ipEntries[i], entryType)
  }
  for i := range infoFinished {
    <-infoFinished[i]
  }
  for i := range ipFinished {
    <-ipFinished[i]
  }

  year,month,day := date[0].Date()
  sYear := strconv.Itoa(year)
  sMonth := month.String()
  sDay := strconv.Itoa(day)

  logDate := fmt.Sprintf("%s/%s/%s", sMonth, sDay, sYear)

  logStats.setDate(logDate)
  logStats.setDuration(difference.String())
  logStats.setTime(timeAvg)
  logStats.setLength(length)

  fmt.Print("Length: ")
  fmt.Println(length)
  fmt.Print("Duration: ")
  fmt.Println(difference)
  fmt.Print("Time Average: ")
  fmt.Println(timeAvg)

  data <- logStats
  fmt.Println("Grrarrr")
}

func getEntries(lines []string, mobileType string, data chan logData) {
  var entry userInfo
  entries := make([]userInfo, 0)
  logStats := make(chan logData)

  for i := 0; i < len(lines); i++ {
    finalLine := trimString(lines[i])
    lineParts := strings.Split(finalLine, " ")
    time := 0

    status,_ := strconv.Atoi(lineParts[6])
    dateArray := []string{lineParts[1], lineParts[2]}
    date := strings.Join(dateArray, " ")

    if(len(lineParts) > 7) {
      time,_ = strconv.Atoi(lineParts[7])
    }

    entry.setIp(lineParts[0])
    entry.setDate(date)
    entry.setRequestType(lineParts[3])
    entry.setUrl(lineParts[4])
    entry.setProtocol(lineParts[5])
    entry.setStatus(status)
    entry.setTime(time)

    entries = append(entries, entry)
  }

  analyseEntries(entries, mobileType, logStats)
  finalLogStat := <-logStats
  fmt.Println("got stats")
  fmt.Println(finalLogStat)
  data <- finalLogStat
}

func getData(arg string, finished chan bool) {
  androidLogData := make(chan logData)
  iosLogData := make(chan logData)
  error := false

  iosLog,err := os.Open(arg)
  if err != nil {
    fmt.Printf("%s could not be found\n", arg)
    error = true
  }

  if(!error) {
    androidLog,_ := os.Open(arg)
    iosLines := grepLines(iosLog, "iOS")
    androidLines := grepLines(androidLog, "android")
    go getEntries(iosLines, "iOS", iosLogData)
    go getEntries(androidLines, "android", androidLogData)
    fmt.Println("got data")
    iosData := <-iosLogData
    androidData := <-androidLogData

    insertLogDataRow(logDataInsert, androidData, iosData)
  }

  finished <- true
}

func main() {
  start := time.Now()
  var c config
  finished := make([]chan bool, len(os.Args) - 1)
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
      go getData(os.Args[i], finished[i - 1])
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
