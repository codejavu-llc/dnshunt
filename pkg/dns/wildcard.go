package dns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
)

type WildcardProfile struct {
	Domain  string   `json:"domain"`
	QType   string   `json:"record_type"`
	Answers []string `json:"answers"`
	set     map[string]bool
}

// DetectWildcard probes unpredictable names below domain and collects the
// response pool. Multiple probes account for round-robin wildcard records.
func DetectWildcard(ctx context.Context, domain string, qtype uint16, qtypeName string, resolvers []string, opts ResolveOptions, tests int) (*WildcardProfile, int, error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return nil, 0, fmt.Errorf("wildcard domain cannot be empty")
	}
	results := make([]Result, tests)
	errCh := make(chan error, tests)
	var wg sync.WaitGroup
	for i := 0; i < tests; i++ {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, 0, fmt.Errorf("generate wildcard probe: %w", err)
		}
		probe := "dnshunt-" + hex.EncodeToString(random[:]) + "." + domain
		wg.Add(1)
		go func(index int, target string) {
			defer wg.Done()
			if ctx.Err() != nil {
				errCh <- ctx.Err()
				return
			}
			results[index] = ResolveTarget(ctx, target, qtype, qtypeName, resolvers, opts)
		}(i, probe)
	}
	wg.Wait()
	close(errCh)
	if err := <-errCh; err != nil {
		return nil, 0, err
	}

	profile := &WildcardProfile{Domain: domain, QType: strings.ToUpper(qtypeName), set: make(map[string]bool)}
	queries := 0
	for _, result := range results {
		queries += ResultQueryCount(result)
		for _, observed := range result.ObservedAnswers {
			profile.set[observed.Answer] = true
		}
	}
	for answer := range profile.set {
		profile.Answers = append(profile.Answers, answer)
	}
	sort.Strings(profile.Answers)
	if len(profile.Answers) == 0 {
		return nil, queries, nil
	}
	return profile, queries, nil
}

func (p *WildcardProfile) Match(result Result) bool {
	queryType := result.QueryType
	if queryType == "" {
		queryType = result.RecordType
	}
	if p == nil || !strings.EqualFold(p.QType, queryType) {
		return false
	}
	target := strings.ToLower(strings.TrimSuffix(result.Target, "."))
	if target == p.Domain || !strings.HasSuffix(target, "."+p.Domain) {
		return false
	}
	if len(result.Answers) == 0 {
		return false
	}
	for _, answer := range result.Answers {
		if !p.set[answer] {
			return false
		}
	}
	return true
}

func ResultQueryCount(result Result) int {
	total := 0
	for _, response := range result.Resolvers {
		total += response.Queries
	}
	return total
}
