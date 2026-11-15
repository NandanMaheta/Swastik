package ipos

import (
	"reflect"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/NandanMaheta/swastik/apps/api/internal/platform/istdate"
)

// Wire types of the IPO operations (contracts/ipos.openapi.yaml). Money is integer paise; dates are
// IST civil dates (YYYY-MM-DD). Request schemas accept any short segment string so the service can
// answer ipo.sme_not_allowed and ipo.invalid_segment (research R-05).

const (
	wireNSE = "NSE_MAINBOARD"
	wireBSE = "BSE_MAINBOARD"

	statusEnum = "UPCOMING,OPEN,CLOSED,ALLOTMENT_OUT,LISTED,SETTLED"
	flagEnum   = "APPLY,DO_NOT_APPLY"
)

// IPODates are the six IST dates; null means not set. On PUT every key is required.
type IPODates struct {
	OpenDate        *string `json:"open_date" format:"date" nullable:"true"`
	CloseDate       *string `json:"close_date" format:"date" nullable:"true"`
	AllotmentDate   *string `json:"allotment_date" format:"date" nullable:"true"`
	RefundDate      *string `json:"refund_date" format:"date" nullable:"true"`
	DematCreditDate *string `json:"demat_credit_date" format:"date" nullable:"true"`
	ListingDate     *string `json:"listing_date" format:"date" nullable:"true"`
}

// IPODraft is the create body: only name and segments are required.
type IPODraft struct {
	Name                string    `json:"name" minLength:"1" maxLength:"200"`
	Segments            []string  `json:"segments" minItems:"1" maxItems:"4" doc:"NSE_MAINBOARD and/or BSE_MAINBOARD. NSE_EMERGE and BSE_SME give ipo.sme_not_allowed; other values or repeats give ipo.invalid_segment."`
	NSESymbol           *string   `json:"nse_symbol,omitempty" pattern:"^[A-Z0-9&-]{1,20}$" nullable:"true"`
	IssueSizePaise      *int64    `json:"issue_size_paise,omitempty" minimum:"1" maximum:"1000000000000000" nullable:"true"`
	PriceBandFloorPaise *int64    `json:"price_band_floor_paise,omitempty" minimum:"1" maximum:"1000000000" nullable:"true"`
	PriceBandCapPaise   *int64    `json:"price_band_cap_paise,omitempty" minimum:"1" maximum:"1000000000" nullable:"true"`
	IssuePricePaise     *int64    `json:"issue_price_paise,omitempty" minimum:"1" maximum:"1000000000" nullable:"true"`
	LotSize             *int32    `json:"lot_size,omitempty" minimum:"1" maximum:"1000000" nullable:"true"`
	Dates               *IPODates `json:"dates,omitempty"`
	Registrar           *string   `json:"registrar,omitempty" minLength:"1" maxLength:"200" nullable:"true"`
	LeadManagers        []string  `json:"lead_managers,omitempty" maxItems:"20"`
	OfferDocumentURL    *string   `json:"offer_document_url,omitempty" format:"uri" pattern:"^https://" maxLength:"2000" nullable:"true"`
}

// IPOReplace is the PUT body: every key is required and null clears.
type IPOReplace struct {
	Version             int32    `json:"version" minimum:"1"`
	Name                string   `json:"name" minLength:"1" maxLength:"200"`
	Segments            []string `json:"segments" minItems:"1" maxItems:"4"`
	NSESymbol           *string  `json:"nse_symbol" pattern:"^[A-Z0-9&-]{1,20}$" nullable:"true"`
	IssueSizePaise      *int64   `json:"issue_size_paise" minimum:"1" maximum:"1000000000000000" nullable:"true"`
	PriceBandFloorPaise *int64   `json:"price_band_floor_paise" minimum:"1" maximum:"1000000000" nullable:"true"`
	PriceBandCapPaise   *int64   `json:"price_band_cap_paise" minimum:"1" maximum:"1000000000" nullable:"true"`
	IssuePricePaise     *int64   `json:"issue_price_paise" minimum:"1" maximum:"1000000000" nullable:"true"`
	LotSize             *int32   `json:"lot_size" minimum:"1" maximum:"1000000" nullable:"true"`
	Dates               IPODates `json:"dates"`
	Registrar           *string  `json:"registrar" minLength:"1" maxLength:"200" nullable:"true"`
	LeadManagers        []string `json:"lead_managers" maxItems:"20"`
	OfferDocumentURL    *string  `json:"offer_document_url" format:"uri" pattern:"^https://" maxLength:"2000" nullable:"true"`
}

// VersionBody carries the optimistic-lock version.
type VersionBody struct {
	Version int32 `json:"version" minimum:"1"`
}

// FlagBody sets or clears the apply flag and its client-visible note.
type FlagBody struct {
	Version   int32   `json:"version" minimum:"1"`
	ApplyFlag *string `json:"apply_flag" enum:"APPLY,DO_NOT_APPLY" nullable:"true"`
	FlagNote  *string `json:"flag_note" minLength:"1" maxLength:"500" nullable:"true" doc:"Shown to clients."`
}

// StatusBody is a manual status override.
type StatusBody struct {
	Version int32  `json:"version" minimum:"1"`
	Status  string `json:"status" enum:"UPCOMING,OPEN,CLOSED,ALLOTMENT_OUT,LISTED,SETTLED"`
	Reason  string `json:"reason" minLength:"1" maxLength:"500"`
}

// IPOFacts are the fields the admin and client views share.
type IPOFacts struct {
	ID                  string   `json:"id" format:"uuid"`
	Name                string   `json:"name"`
	Segments            []string `json:"segments"`
	NSESymbol           *string  `json:"nse_symbol" nullable:"true"`
	IssueSizePaise      *int64   `json:"issue_size_paise" nullable:"true"`
	PriceBandFloorPaise *int64   `json:"price_band_floor_paise" nullable:"true"`
	PriceBandCapPaise   *int64   `json:"price_band_cap_paise" nullable:"true"`
	IssuePricePaise     *int64   `json:"issue_price_paise" nullable:"true"`
	LotSize             *int32   `json:"lot_size" nullable:"true"`
	MinApplicationPaise *int64   `json:"min_application_paise" nullable:"true" doc:"lot x final price, else lot x band cap"`
	Dates               IPODates `json:"dates"`
	Registrar           *string  `json:"registrar" nullable:"true"`
	LeadManagers        []string `json:"lead_managers"`
	OfferDocumentURL    *string  `json:"offer_document_url" nullable:"true"`
	Status              string   `json:"status" enum:"UPCOMING,OPEN,CLOSED,ALLOTMENT_OUT,LISTED,SETTLED"`
	UpdatedAt           string   `json:"updated_at" format:"date-time"`
}

// ClientIPO is a published IPO as clients see it. It never carries the source, override reasons,
// audit history or the version (FR-051).
//
// Schema is declared (and never filled) so Huma does not wrap the body with its own "$schema" key:
// the client view has an exact, minimal set of keys.
type ClientIPO struct {
	Schema string `json:"$schema,omitempty" readOnly:"true" doc:"Unused; always absent."`
	IPOFacts
	ApplyFlag *string `json:"apply_flag" enum:"APPLY,DO_NOT_APPLY"`
	FlagNote  *string `json:"flag_note" nullable:"true"`
}

// AdminIPO is the operator view of an IPO.
type AdminIPO struct {
	IPOFacts
	ApplyFlag       *string `json:"apply_flag" enum:"APPLY,DO_NOT_APPLY" nullable:"true"`
	FlagNote        *string `json:"flag_note" nullable:"true"`
	Eligible        bool    `json:"eligible" doc:"published and APPLY"`
	Published       bool    `json:"published"`
	EverPublished   bool    `json:"ever_published"`
	StatusSource    string  `json:"status_source" enum:"schedule,admin,settlement"`
	StatusChangedAt string  `json:"status_changed_at" format:"date-time"`
	Source          string  `json:"source" example:"manual"`
	SourceRef       *string `json:"source_ref" nullable:"true"`
	LastSyncedAt    *string `json:"last_synced_at" format:"date-time" nullable:"true"`
	Version         int32   `json:"version"`
	CreatedAt       string  `json:"created_at" format:"date-time"`
}

// warningBody is the wire form of Warning; it is registered as the schema "Warning".
type warningBody struct {
	Code   string           `json:"code" example:"ipo.min_application_out_of_range"`
	Fields []string         `json:"fields"`
	Detail string           `json:"detail"`
	Params map[string]int64 `json:"params"`
}

// Schema registers warningBody under the name Warning (the Go type Warning is the domain value).
func (warningBody) Schema(r huma.Registry) *huma.Schema {
	return registerAs(r, "Warning", reflect.TypeOf(struct {
		Code   string           `json:"code" example:"ipo.min_application_out_of_range"`
		Fields []string         `json:"fields"`
		Detail string           `json:"detail"`
		Params map[string]int64 `json:"params"`
	}{}))
}

// IPOMutationResult is what every mutation returns.
type IPOMutationResult struct {
	IPO      AdminIPO      `json:"ipo"`
	Warnings []warningBody `json:"warnings"`
}

// AdminIPOPage is one page of the admin list.
type AdminIPOPage struct {
	Items      []AdminIPO `json:"items"`
	NextCursor *string    `json:"next_cursor" nullable:"true"`
}

// ClientIPOPage is one page of the client list.
type ClientIPOPage struct {
	Items      []ClientIPO `json:"items"`
	NextCursor *string     `json:"next_cursor" nullable:"true"`
}

// dateSuggestionBody is the wire form of DateSuggestion; it is registered as "DateSuggestion".
type dateSuggestionBody struct {
	CloseDate       string `json:"close_date" format:"date"`
	AllotmentDate   string `json:"allotment_date" format:"date"`
	RefundDate      string `json:"refund_date" format:"date"`
	DematCreditDate string `json:"demat_credit_date" format:"date"`
	ListingDate     string `json:"listing_date" format:"date"`
	NoticeCode      string `json:"notice_code" example:"ipo.weekdays_only"`
	Notice          string `json:"notice" example:"weekdays only; check exchange holidays"`
}

// Schema registers dateSuggestionBody under the name DateSuggestion.
func (dateSuggestionBody) Schema(r huma.Registry) *huma.Schema {
	return registerAs(r, "DateSuggestion", reflect.TypeOf(struct {
		CloseDate       string `json:"close_date" format:"date"`
		AllotmentDate   string `json:"allotment_date" format:"date"`
		RefundDate      string `json:"refund_date" format:"date"`
		DematCreditDate string `json:"demat_credit_date" format:"date"`
		ListingDate     string `json:"listing_date" format:"date"`
		NoticeCode      string `json:"notice_code" example:"ipo.weekdays_only"`
		Notice          string `json:"notice" example:"weekdays only; check exchange holidays"`
	}{}))
}

// registerAs registers the schema of an anonymous struct under name and returns a reference to it.
func registerAs(r huma.Registry, name string, t reflect.Type) *huma.Schema {
	if _, ok := r.Map()[name]; !ok {
		r.Map()[name] = r.Schema(t, false, name)
	}
	return &huma.Schema{Ref: "#/components/schemas/" + name}
}

// ---- domain to wire ----

func wireSegments(ex []Exchange) []string {
	out := make([]string, 0, len(ex))
	for _, e := range ex {
		switch e {
		case ExchangeNSE:
			out = append(out, wireNSE)
		case ExchangeBSE:
			out = append(out, wireBSE)
		}
	}
	return out
}

func exchangesOf(segs []string) []Exchange {
	out := make([]Exchange, 0, len(segs))
	for _, s := range segs {
		switch s {
		case wireNSE:
			out = append(out, ExchangeNSE)
		case wireBSE:
			out = append(out, ExchangeBSE)
		default:
			out = append(out, Exchange(s)) // refused by validation: SME or unknown
		}
	}
	return out
}

func datesOut(d Dates) IPODates {
	f := func(x *istdate.Date) *string {
		if x == nil {
			return nil
		}
		s := x.String()
		return &s
	}
	return IPODates{OpenDate: f(d.Open), CloseDate: f(d.Close), AllotmentDate: f(d.Allotment),
		RefundDate: f(d.Refund), DematCreditDate: f(d.DematCredit), ListingDate: f(d.Listing)}
}

// datesIn parses dates the schema already validated as YYYY-MM-DD.
func datesIn(d IPODates) Dates {
	f := func(s *string) *istdate.Date {
		if s == nil {
			return nil
		}
		x, err := istdate.ParseDate(*s)
		if err != nil {
			return nil
		}
		return &x
	}
	return Dates{Open: f(d.OpenDate), Close: f(d.CloseDate), Allotment: f(d.AllotmentDate),
		Refund: f(d.RefundDate), DematCredit: f(d.DematCreditDate), Listing: f(d.ListingDate)}
}

func (b IPODraft) draft() Draft {
	d := Draft{
		Name: b.Name, Exchanges: exchangesOf(b.Segments), NSESymbol: b.NSESymbol, IssueSizePaise: b.IssueSizePaise,
		PriceBandFloorPaise: b.PriceBandFloorPaise, PriceBandCapPaise: b.PriceBandCapPaise,
		IssuePricePaise: b.IssuePricePaise, LotSize: b.LotSize, Registrar: b.Registrar,
		LeadManagers: b.LeadManagers, OfferDocumentURL: b.OfferDocumentURL,
	}
	if b.Dates != nil {
		d.Dates = datesIn(*b.Dates)
	}
	return d
}

func (b IPOReplace) draft() Draft {
	return Draft{
		Name: b.Name, Exchanges: exchangesOf(b.Segments), NSESymbol: b.NSESymbol, IssueSizePaise: b.IssueSizePaise,
		PriceBandFloorPaise: b.PriceBandFloorPaise, PriceBandCapPaise: b.PriceBandCapPaise,
		IssuePricePaise: b.IssuePricePaise, LotSize: b.LotSize, Dates: datesIn(b.Dates), Registrar: b.Registrar,
		LeadManagers: b.LeadManagers, OfferDocumentURL: b.OfferDocumentURL,
	}
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func factsOut(i IPO) IPOFacts {
	var minApp *int64
	if v, ok := i.MinApplicationPaise(); ok {
		minApp = &v
	}
	managers := i.LeadManagers
	if managers == nil {
		managers = []string{}
	}
	return IPOFacts{
		ID: i.ID.String(), Name: i.Name, Segments: wireSegments(i.Exchanges), NSESymbol: i.NSESymbol,
		IssueSizePaise: i.IssueSizePaise, PriceBandFloorPaise: i.PriceBandFloorPaise,
		PriceBandCapPaise: i.PriceBandCapPaise, IssuePricePaise: i.IssuePricePaise, LotSize: i.LotSize,
		MinApplicationPaise: minApp, Dates: datesOut(i.Dates), Registrar: i.Registrar, LeadManagers: managers,
		OfferDocumentURL: i.OfferDocumentURL, Status: string(i.Status), UpdatedAt: rfc3339(i.UpdatedAt),
	}
}

func flagOut(f *ApplyFlag) *string {
	if f == nil {
		return nil
	}
	s := string(*f)
	return &s
}

func adminOut(i IPO) AdminIPO {
	var synced *string
	if i.LastSyncedAt != nil {
		s := rfc3339(*i.LastSyncedAt)
		synced = &s
	}
	return AdminIPO{
		IPOFacts: factsOut(i), ApplyFlag: flagOut(i.Flag), FlagNote: i.FlagNote, Eligible: i.Eligible(),
		Published: i.Published, EverPublished: i.FirstPublishedAt != nil, StatusSource: string(i.StatusSource),
		StatusChangedAt: rfc3339(i.StatusChangedAt), Source: i.Source, SourceRef: i.SourceRef,
		LastSyncedAt: synced, Version: i.Version, CreatedAt: rfc3339(i.CreatedAt),
	}
}

func clientOut(i IPO) ClientIPO {
	return ClientIPO{IPOFacts: factsOut(i), ApplyFlag: flagOut(i.Flag), FlagNote: i.FlagNote}
}

func resultOut(r Result) IPOMutationResult {
	ws := make([]warningBody, 0, len(r.Warnings))
	for _, w := range r.Warnings {
		fields := w.Fields
		if fields == nil {
			fields = []string{}
		}
		ws = append(ws, warningBody{Code: w.Code, Fields: fields, Detail: w.Detail, Params: w.Params})
	}
	return IPOMutationResult{IPO: adminOut(r.IPO), Warnings: ws}
}

func cursorOut(next string) *string {
	if next == "" {
		return nil
	}
	return &next
}
