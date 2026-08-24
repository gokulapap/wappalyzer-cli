package scanner

import (
	"sort"
	"strings"
)

const maxEvidencePerTechnology = 20

type technologySet struct {
	detector *enhancedDetector
	items    map[string]*technologyDetection
}

type technologyDetection struct {
	name           string
	version        string
	confidence     int
	evidence       []Evidence
	evidenceKeys   map[string]struct{}
	confidenceKeys map[string]struct{}
}

func newTechnologySet(detector *enhancedDetector) *technologySet {
	return &technologySet{detector: detector, items: make(map[string]*technologyDetection)}
}

func (s *technologySet) Add(signal detectionSignal) bool {
	if strings.TrimSpace(signal.Name) == "" {
		return false
	}
	signal.Confidence = normalizedConfidence(signal.Confidence)
	item, exists := s.items[signal.Name]
	if !exists {
		item = &technologyDetection{
			name:           signal.Name,
			evidenceKeys:   make(map[string]struct{}),
			confidenceKeys: make(map[string]struct{}),
		}
		s.items[signal.Name] = item
	}

	evidenceKey := signal.Evidence.Type + "\x00" + signal.Evidence.Value + "\x00" + signal.Evidence.URL
	if _, duplicate := item.evidenceKeys[evidenceKey]; !duplicate {
		item.evidenceKeys[evidenceKey] = struct{}{}
		if len(item.evidence) < maxEvidencePerTechnology {
			item.evidence = append(item.evidence, signal.Evidence)
		}
	}
	confidenceKey := signal.Evidence.Type + "\x00" + signal.Evidence.Value
	if _, duplicate := item.confidenceKeys[confidenceKey]; !duplicate {
		item.confidenceKeys[confidenceKey] = struct{}{}
		item.confidence = combineConfidence(item.confidence, signal.Confidence)
	}
	if moreSpecificVersion(signal.Version, item.version) {
		item.version = signal.Version
	}
	return !exists
}

func (s *technologySet) AddAll(signals []detectionSignal) {
	for _, signal := range signals {
		s.Add(signal)
	}
}

func (s *technologySet) AddImplications() {
	queue := make([]string, 0, len(s.items))
	for name := range s.items {
		queue = append(queue, name)
	}
	sort.Strings(queue)
	processed := make(map[string]struct{}, len(queue))
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if _, done := processed[name]; done {
			continue
		}
		processed[name] = struct{}{}
		source := s.items[name]
		metadata := s.detector.Metadata(name)
		for _, implied := range metadata.Implies {
			confidence := max(1, source.confidence*implied.Confidence/100)
			added := s.Add(detectionSignal{
				Name:       implied.Name,
				Version:    implied.Version,
				Confidence: confidence,
				Evidence: Evidence{
					Type:  "implied",
					Value: name,
				},
			})
			if added {
				queue = append(queue, implied.Name)
			}
		}
	}
}

func (s *technologySet) Technologies(categoryFilters []string, minimumConfidence int) []Technology {
	technologies := make([]Technology, 0, len(s.items))
	for name, item := range s.items {
		if item.confidence < minimumConfidence {
			continue
		}
		metadata := s.detector.Metadata(name)
		if !matchesCategories(metadata.Categories, categoryFilters) {
			continue
		}
		evidence := append([]Evidence(nil), item.evidence...)
		sort.Slice(evidence, func(i, j int) bool {
			if evidence[i].Type != evidence[j].Type {
				return evidence[i].Type < evidence[j].Type
			}
			if evidence[i].URL != evidence[j].URL {
				return evidence[i].URL < evidence[j].URL
			}
			return evidence[i].Value < evidence[j].Value
		})
		technologies = append(technologies, Technology{
			Name:        name,
			Version:     item.version,
			Confidence:  item.confidence,
			Categories:  append([]string(nil), metadata.Categories...),
			Description: metadata.Description,
			Website:     metadata.Website,
			CPE:         metadata.CPE,
			Evidence:    evidence,
		})
	}
	sort.Slice(technologies, func(i, j int) bool {
		if technologies[i].Name == technologies[j].Name {
			return technologies[i].Version < technologies[j].Version
		}
		return technologies[i].Name < technologies[j].Name
	})
	return technologies
}

func combineConfidence(current, additional int) int {
	if current <= 0 {
		return additional
	}
	return min(current+additional, 100)
}

func moreSpecificVersion(candidate, current string) bool {
	candidate = strings.TrimSpace(candidate)
	current = strings.TrimSpace(current)
	if candidate == "" {
		return false
	}
	if current == "" {
		return true
	}
	return len(candidate) > len(current) || (len(candidate) == len(current) && candidate < current)
}
