package scanner

import "testing"

func TestTechnologySetCombinesIndependentConfidenceAndDeduplicatesEvidence(t *testing.T) {
	t.Parallel()
	detector := &enhancedDetector{metadata: map[string]technologyMetadata{}}
	set := newTechnologySet(detector)
	evidence := Evidence{Type: "dom", Value: "#app", URL: "https://example.com"}
	set.Add(detectionSignal{Name: "Example", Confidence: 50, Evidence: evidence})
	set.Add(detectionSignal{Name: "Example", Confidence: 50, Evidence: evidence})
	set.Add(detectionSignal{Name: "Example", Confidence: 50, Evidence: Evidence{
		Type: "dom", Value: "#app", URL: "https://example.com/about",
	}})
	set.Add(detectionSignal{Name: "Example", Version: "2.1.0", Confidence: 50, Evidence: Evidence{
		Type: "javascript", Value: "Example.version", URL: "https://example.com",
	}})

	technologies := set.Technologies(nil, 1)
	if len(technologies) != 1 {
		t.Fatalf("technologies = %#v, want one", technologies)
	}
	technology := technologies[0]
	if technology.Confidence != 100 || technology.Version != "2.1.0" || len(technology.Evidence) != 3 {
		t.Fatalf("technology = %#v, want 100%% confidence, version 2.1.0, and three evidence items", technology)
	}
}

func TestTechnologySetAddsTransitiveImplications(t *testing.T) {
	t.Parallel()
	detector := &enhancedDetector{metadata: map[string]technologyMetadata{
		"Framework": {Implies: []implication{{Name: "Runtime", Confidence: 80}}},
		"Runtime":   {Implies: []implication{{Name: "Language", Confidence: 50}}},
	}}
	set := newTechnologySet(detector)
	set.Add(detectionSignal{Name: "Framework", Confidence: 90, Evidence: Evidence{Type: "dom", Value: "#app"}})
	set.AddImplications()

	technologies := set.Technologies(nil, 1)
	runtime := technologyByName(technologies, "Runtime")
	language := technologyByName(technologies, "Language")
	if runtime == nil || runtime.Confidence != 72 {
		t.Fatalf("Runtime = %#v, want 72%% confidence", runtime)
	}
	if language == nil || language.Confidence != 36 {
		t.Fatalf("Language = %#v, want 36%% confidence", language)
	}
}

func TestTechnologySetFiltersByMinimumConfidence(t *testing.T) {
	t.Parallel()
	detector := &enhancedDetector{metadata: map[string]technologyMetadata{}}
	set := newTechnologySet(detector)
	set.Add(detectionSignal{Name: "Weak", Confidence: 49, Evidence: Evidence{Type: "dom", Value: ".maybe"}})
	set.Add(detectionSignal{Name: "Strong", Confidence: 80, Evidence: Evidence{Type: "dom", Value: "#certain"}})

	technologies := set.Technologies(nil, 50)
	if len(technologies) != 1 || technologies[0].Name != "Strong" {
		t.Fatalf("technologies = %#v, want only Strong", technologies)
	}
}
