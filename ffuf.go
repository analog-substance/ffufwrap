package ffuf

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	DefaultStrategy RecursionStrategy = "default"
	GreedyStrategy  RecursionStrategy = "greedy"

	BasicStrategy    AutoCalibrateStrategy = "basic"
	AdvancedStrategy AutoCalibrateStrategy = "advanced"

	OrOperator  SetOperator = "or"
	AndOperator SetOperator = "and"

	ModeClusterBomb WordlistMode = "clusterbomb"
	ModePitchFork   WordlistMode = "pitchfork"
	ModeSniper      WordlistMode = "sniper"

	FormatAll      OutputFormat = "all"
	FormatJSON     OutputFormat = "json"
	FormatEJSON    OutputFormat = "ejson"
	FormatHTML     OutputFormat = "html"
	FormatMarkdown OutputFormat = "md"
	FormatCSV      OutputFormat = "csv"
	FormatECSV     OutputFormat = "ecsv"
)

type RecursionStrategy string
type AutoCalibrateStrategy string
type SetOperator string
type WordlistMode string
type OutputFormat string

type Fuzzer struct {
	args []string
	// binaryPath string
	ctx context.Context
}

func NewFuzzer(ctx context.Context) *Fuzzer {
	return &Fuzzer{
		args: make([]string, 0),
		ctx:  ctx,
	}
}

func (f *Fuzzer) addArgs(args ...string) {
	f.args = append(f.args, args...)
}

func (f *Fuzzer) Clone(ctx context.Context) *Fuzzer {
	args := make([]string, len(f.args))
	copy(args, f.args)

	return &Fuzzer{
		args: args,
		ctx:  ctx,
	}
}

// Headers adds the headers from each key value pair in the map
func (f *Fuzzer) Headers(headers map[string]string) *Fuzzer {
	for key, value := range headers {
		f.addArgs("-H", fmt.Sprintf("%s: %s", key, value))
	}
	return f
}

// Header adds the header key value pair
func (f *Fuzzer) Header(key string, value string) *Fuzzer {
	f.addArgs("-H", fmt.Sprintf("%s: %s", key, value))
	return f
}

func (f *Fuzzer) RecursionDepth(depth int) *Fuzzer {
	f.addArgs("-recursion-depth", fmt.Sprintf("%d", depth))
	return f
}

func (f *Fuzzer) Recursion() *Fuzzer {
	f.addArgs("-recursion")
	return f
}

func (f *Fuzzer) RecursionStrategy(strategy RecursionStrategy) *Fuzzer {
	f.addArgs("-recursion-strategy", string(strategy))
	return f
}

func (f *Fuzzer) ReplayProxy() *Fuzzer {
	f.addArgs("-replay-proxy")
	return f
}

func (f *Fuzzer) SNI() *Fuzzer {
	f.addArgs("-sni")
	return f
}

func (f *Fuzzer) Timeout(timeout int) *Fuzzer {
	f.addArgs("-timeout", fmt.Sprintf("%d", timeout))
	return f
}

func (f *Fuzzer) AutoCalibrate() *Fuzzer {
	f.addArgs("-ac")
	return f
}

func (f *Fuzzer) CustomAutoCalibrate(items ...string) *Fuzzer {
	for _, item := range items {
		f.addArgs("-acc", item)
	}
	return f
}

func (f *Fuzzer) PerHostAutoCalibrate() *Fuzzer {
	f.addArgs("-ach")
	return f
}

func (f *Fuzzer) AutoCalibrateStrategy(strategy AutoCalibrateStrategy) *Fuzzer {
	f.addArgs("-acs", string(strategy))
	return f
}

func (f *Fuzzer) ColorizeOutput() *Fuzzer {
	f.addArgs("-c")
	return f
}

func (f *Fuzzer) ConfigFile(file string) *Fuzzer {
	f.addArgs("-config", file)
	return f
}

func (f *Fuzzer) PrintJSON() *Fuzzer {
	f.addArgs("-json")
	return f
}

func (f *Fuzzer) MaxTotalTime(max int) *Fuzzer {
	f.addArgs("-maxtime", fmt.Sprintf("%d", max))
	return f
}

func (f *Fuzzer) MaxJobTime(max int) *Fuzzer {
	f.addArgs("-maxtime-job", fmt.Sprintf("%d", max))
	return f
}

func (f *Fuzzer) NonInteractive() *Fuzzer {
	f.addArgs("-noninteractive")
	return f
}

func (f *Fuzzer) RequestRate(rate int) *Fuzzer {
	f.addArgs("-rate", fmt.Sprintf("%d", rate))
	return f
}

func (f *Fuzzer) Silent() *Fuzzer {
	f.addArgs("-silent")
	return f
}

func (f *Fuzzer) StopOnAllErrors() *Fuzzer {
	f.addArgs("-sa")
	return f
}

func (f *Fuzzer) StopOnSpuriousErrors() *Fuzzer {
	f.addArgs("-se")
	return f
}

func (f *Fuzzer) StopOnForbidden() *Fuzzer {
	f.addArgs("-sf")
	return f
}

func (f *Fuzzer) Threads(threads int) *Fuzzer {
	f.addArgs("-t", fmt.Sprintf("%d", threads))
	return f
}

func (f *Fuzzer) Verbose() *Fuzzer {
	f.addArgs("-v")
	return f
}

func (f *Fuzzer) Method(method string) *Fuzzer {
	f.addArgs("-X", method)
	return f
}

func (f *Fuzzer) Delay(delay int) *Fuzzer {
	f.addArgs("-p", fmt.Sprintf("%d", delay))
	return f
}

func (f *Fuzzer) Exts(exts []string) *Fuzzer {
	f.addArgs("-e", strings.Join(exts, ","))
	return f
}

func (f *Fuzzer) MatchCodes(codes ...string) *Fuzzer {
	f.addArgs("-mc", strings.Join(codes, ","))
	return f
}

func (f *Fuzzer) MatchLines(count int) *Fuzzer {
	f.addArgs("-ml", fmt.Sprintf("%d", count))
	return f
}

func (f *Fuzzer) MatchSize(size int) *Fuzzer {
	f.addArgs("-ms", fmt.Sprintf("%d", size))
	return f
}

func (f *Fuzzer) MatchWords(count int) *Fuzzer {
	f.addArgs("-mw", fmt.Sprintf("%d", count))
	return f
}

func (f *Fuzzer) MatchRegex(re string) *Fuzzer {
	f.addArgs("-mr", re)
	return f
}

func (f *Fuzzer) MatchTime(milliseconds int) *Fuzzer {
	f.addArgs("-mt", fmt.Sprintf("%d", milliseconds))
	return f
}

func (f *Fuzzer) MatchOperator(op SetOperator) *Fuzzer {
	f.addArgs("-mmode", string(op))
	return f
}

func (f *Fuzzer) FilterCodes(codes ...string) *Fuzzer {
	f.addArgs("-fc", strings.Join(codes, ","))
	return f
}

func (f *Fuzzer) FilterLines(count int) *Fuzzer {
	f.addArgs("-fl", fmt.Sprintf("%d", count))
	return f
}

func (f *Fuzzer) FilterSize(size int) *Fuzzer {
	f.addArgs("-fs", fmt.Sprintf("%d", size))
	return f
}

func (f *Fuzzer) FilterWords(count int) *Fuzzer {
	f.addArgs("-fw", fmt.Sprintf("%d", count))
	return f
}

func (f *Fuzzer) FilterRegex(re string) *Fuzzer {
	f.addArgs("-fr", re)
	return f
}

func (f *Fuzzer) FilterOperator(op SetOperator) *Fuzzer {
	f.addArgs("-fmode", string(op))
	return f
}

func (f *Fuzzer) FilterTime(milliseconds int) *Fuzzer {
	f.addArgs("-ft", fmt.Sprintf("%d", milliseconds))
	return f
}

func (f *Fuzzer) Authorization(value string) *Fuzzer {
	return f.Header("Authorization", value)
}

func (f *Fuzzer) BearerToken(token string) *Fuzzer {
	return f.Authorization(fmt.Sprintf("Bearer %s", token))
}

func (f *Fuzzer) Proxy(proxy string) *Fuzzer {
	f.addArgs("-x", proxy)
	return f
}

func (f *Fuzzer) Cookie(data string) *Fuzzer {
	f.addArgs("-b", data)
	return f
}

func (f *Fuzzer) PostString(data string) *Fuzzer {
	f.addArgs("-d", data)
	return f
}

func (f *Fuzzer) PostJSON(v interface{}) *Fuzzer {
	data, _ := json.Marshal(v)
	f.addArgs("-d", string(data))
	return f
}

func (f *Fuzzer) Target(url string) *Fuzzer {
	f.addArgs("-u", url)
	return f
}

func (f *Fuzzer) UserAgent(agent string) *Fuzzer {
	return f.Header("User-Agent", agent)
}

func (f *Fuzzer) HTTP2() *Fuzzer {
	f.addArgs("-http2")
	return f
}

func (f *Fuzzer) IgnoreBody() *Fuzzer {
	f.addArgs("-ignore-body")
	return f
}

func (f *Fuzzer) FollowRedirects() *Fuzzer {
	f.addArgs("-r")
	return f
}

func (f *Fuzzer) DirSearchCompat() *Fuzzer {
	f.addArgs("-D")
	return f
}

func (f *Fuzzer) IgnoreWordlistComments() *Fuzzer {
	f.addArgs("-ic")
	return f
}

func (f *Fuzzer) InputCommand(cmd string) *Fuzzer {
	f.addArgs("-input-cmd", cmd)
	return f
}

func (f *Fuzzer) InputNum(num int) *Fuzzer {
	f.addArgs("-input-num", fmt.Sprintf("%d", num))
	return f
}

func (f *Fuzzer) InputShell(shell string) *Fuzzer {
	f.addArgs("-input-shell", shell)
	return f
}

func (f *Fuzzer) WordlistMode(mode WordlistMode) *Fuzzer {
	f.addArgs("-mode", string(mode))
	return f
}

func (f *Fuzzer) RawRequestFile(file string) *Fuzzer {
	f.addArgs("-request", file)
	return f
}

func (f *Fuzzer) RawRequestProtocol(protocol string) *Fuzzer {
	f.addArgs("-request-proto", protocol)
	return f
}

func (f *Fuzzer) Wordlist(wordlist string) *Fuzzer {
	f.addArgs("-w", wordlist)
	return f
}

func (f *Fuzzer) DebugLog(file string) *Fuzzer {
	f.addArgs("-debug-log", file)
	return f
}

func (f *Fuzzer) OutputFile(file string) *Fuzzer {
	f.addArgs("-o", file)
	return f
}

func (f *Fuzzer) OutputDir(dir string) *Fuzzer {
	f.addArgs("-od", dir)
	return f
}

func (f *Fuzzer) OutputFormat(format OutputFormat) *Fuzzer {
	f.addArgs("-of", string(format))
	return f
}

func (f *Fuzzer) NoEmptyOutput() *Fuzzer {
	f.addArgs("-or")
	return f
}

func (f *Fuzzer) CustomArguments(args ...string) *Fuzzer {
	f.addArgs(args...)
	return f
}

func (f *Fuzzer) Args() []string {
	return f.args
}

func (f *Fuzzer) Run() (string, error) {
	return "", nil
}
