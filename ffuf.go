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
)

type RecursionStrategy string
type AutoCalibrateStrategy string

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

func (f *Fuzzer) Wordlist(wordlist string) *Fuzzer {
	f.addArgs("-w", wordlist)
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

func (f *Fuzzer) CustomArguments(args ...string) *Fuzzer {
	f.addArgs(args...)
	return f
}