package ipos

// S16 - the error to problem mapping, driven by the table in contracts/error-codes.md (FR-061).
// Assumption: problemFor(err) error returns a *httpx.ErrorModel (a huma.StatusError) built with
// httpx.Problem; ValidationError issues become errors[] items located at "body.<Field>"
// (error-codes.md: "The field list is added as errors[].location (body.<field>)").

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/httpx"
)

const errorCodesDoc = "../../../../specs/008-ipo-catalogue/contracts/error-codes.md"

type codeRow struct {
	code   string
	status int
}

var codeRowRE = regexp.MustCompile("^\\| `([a-z_.]+)` \\| (\\d{3}) \\|")

// errorRows parses the "Errors" table (not the warnings table).
func errorRows(t *testing.T) []codeRow {
	t.Helper()
	b, err := os.ReadFile(errorCodesDoc)
	if err != nil {
		t.Fatalf("read %s: %v", errorCodesDoc, err)
	}
	doc := string(b)
	if i := strings.Index(doc, "## Warnings"); i > 0 {
		doc = doc[:i]
	}
	var rows []codeRow
	for _, line := range strings.Split(doc, "\n") {
		if m := codeRowRE.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[2])
			rows = append(rows, codeRow{m[1], n})
		}
	}
	if len(rows) < 12 {
		t.Fatalf("parsed %d rows from error-codes.md, want at least 12", len(rows))
	}
	return rows
}

func asProblem(t *testing.T, err error) *httpx.ErrorModel {
	t.Helper()
	var pe *httpx.ErrorModel
	if !errors.As(err, &pe) {
		t.Fatalf("problemFor returned %T (%v), want *httpx.ErrorModel", err, err)
	}
	return pe
}

func mapped(t *testing.T, in error) (pe *httpx.ErrorModel) {
	t.Helper()
	guard(t, "problemFor", func() { pe = asProblem(t, problemFor(in)) })
	return pe
}

// handled maps each documented code to the service error that must produce it. Codes produced by
// Huma or 003 middleware (not by problemFor) are listed in notMapped.
var handled = map[string]error{
	"ipo.sme_not_allowed":         &ValidationError{Code: "ipo.sme_not_allowed", Issues: []FieldIssue{{Field: "segments", Message: "m"}}},
	"ipo.invalid_segment":         &ValidationError{Code: "ipo.invalid_segment", Issues: []FieldIssue{{Field: "segments", Message: "m"}}},
	"ipo.invalid_value":           &ValidationError{Code: "ipo.invalid_value", Issues: []FieldIssue{{Field: "name", Message: "m"}}},
	"ipo.date_order":              &ValidationError{Code: "ipo.date_order", Issues: []FieldIssue{{Field: "open_date", Message: "m"}, {Field: "close_date", Message: "m"}}},
	"ipo.publish_incomplete":      &ValidationError{Code: "ipo.publish_incomplete", Issues: []FieldIssue{{Field: "apply_flag", Message: "m"}, {Field: "lot_size", Message: "m"}}},
	"ipo.idempotency_key_reused":  &ValidationError{Code: "ipo.idempotency_key_reused"},
	"ipo.stale_version":           ErrStaleVersion,
	"ipo.no_change":               ErrNoChange,
	"ipo.published_not_deletable": ErrPublishedNotDeletable,
	"not_found":                   ErrNotFound,
	"internal":                    errors.New("pgx: connection refused to db.internal:5432 password=hunter2"),
}

var notMapped = map[string]bool{"validation_failed": true, "auth.unauthenticated": true, "auth.forbidden": true}

func TestProblems_FR061_EveryDocumentedCodeIsCovered(t *testing.T) {
	for _, r := range errorRows(t) {
		if _, ok := handled[r.code]; !ok && !notMapped[r.code] {
			t.Errorf("error-codes.md documents %q but problems_test.go has no case: add the mapping and a case", r.code)
		}
	}
}

func TestProblems_FR061_StatusCodeAndTypeMatchTheDocument(t *testing.T) {
	for _, r := range errorRows(t) {
		in, ok := handled[r.code]
		if !ok {
			continue
		}
		t.Run(r.code, func(t *testing.T) {
			for name, err := range map[string]error{"direct": in, "wrapped": fmt.Errorf("publish: %w", in)} {
				pe := mapped(t, err)
				if pe.Status != r.status || pe.Code != r.code {
					t.Errorf("%s: got %d %q, want %d %q", name, pe.Status, pe.Code, r.status, r.code)
				}
				if pe.Type != "urn:swastik:problem:"+r.code {
					t.Errorf("%s: type = %q, want urn:swastik:problem:%s", name, pe.Type, r.code)
				}
			}
		})
	}
}

func TestProblems_FR061_ValidationIssuesBecomeLocatedErrors(t *testing.T) {
	pe := mapped(t, handled["ipo.publish_incomplete"])
	if len(pe.Errors) != 2 || pe.Errors[0].Location != "body.apply_flag" || pe.Errors[1].Location != "body.lot_size" {
		t.Fatalf("errors = %+v, want one item per issue at body.apply_flag and body.lot_size", pe.Errors)
	}
	for _, d := range pe.Errors {
		if d.Message == "" || d.Value != nil {
			t.Errorf("item %+v: need a message and never a value", d)
		}
	}
	date := mapped(t, handled["ipo.date_order"])
	if len(date.Errors) != 2 || date.Errors[0].Location != "body.open_date" || date.Errors[1].Location != "body.close_date" {
		t.Errorf("date_order errors = %+v, want one item per field of the pair", date.Errors)
	}
	seg := mapped(t, handled["ipo.sme_not_allowed"])
	if len(seg.Errors) == 0 || seg.Errors[0].Location != "body.segments" {
		t.Errorf("sme_not_allowed errors = %+v, want errors[0].location body.segments", seg.Errors)
	}
}

func TestProblems_FR024_ListenerRejectionKeepsItsCodeAsConflict(t *testing.T) {
	in := &RejectedError{Code: "deal.has_open_tasks", Detail: "2 open tasks"}
	for name, err := range map[string]error{"direct": in, "wrapped": fmt.Errorf("emit: %w", in)} {
		pe := mapped(t, err)
		if pe.Status != 409 || pe.Code != "deal.has_open_tasks" || pe.Detail != "2 open tasks" {
			t.Errorf("%s: got %d %q %q, want 409 deal.has_open_tasks with the listener's detail", name, pe.Status, pe.Code, pe.Detail)
		}
		if pe.Type != "urn:swastik:problem:deal.has_open_tasks" {
			t.Errorf("%s: type = %q", name, pe.Type)
		}
	}
}

func TestProblems_US3_10_UnexpectedErrorsLeakNothing(t *testing.T) {
	pe := mapped(t, handled["internal"])
	body := fmt.Sprintf("%+v", *pe)
	for _, secret := range []string{"hunter2", "db.internal", "5432", "pgx"} {
		if strings.Contains(body, secret) {
			t.Errorf("500 problem contains %q: %s", secret, body)
		}
	}
	if len(pe.Errors) != 0 {
		t.Errorf("500 must carry no details, got %+v", pe.Errors)
	}
}

func TestProblems_FR051_NotFoundBodyIsIdenticalForEveryCause(t *testing.T) {
	a := mapped(t, ErrNotFound)
	b := mapped(t, fmt.Errorf("get %s: %w", "some-uuid", ErrNotFound))
	if fmt.Sprintf("%+v", *a) != fmt.Sprintf("%+v", *b) {
		t.Errorf("not_found problems differ:\n%+v\n%+v", *a, *b)
	}
}

func TestProblems_FR061_DocumentedWarningCodeIsEmitted(t *testing.T) {
	b, err := os.ReadFile(errorCodesDoc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "`ipo.min_application_out_of_range`") {
		t.Fatal("error-codes.md no longer documents ipo.min_application_out_of_range")
	}
	w := warnings(IPO{LotSize: p32(14), PriceBandCapPaise: p64(200_000)})
	if len(w) != 1 || w[0].Code != "ipo.min_application_out_of_range" {
		t.Errorf("warnings = %+v, want the documented code", w)
	}
}
