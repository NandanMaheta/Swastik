package ipomarket

import (
	"reflect"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
)

// GMPEntryInput is the body of ipomarket-record-gmp.
type GMPEntryInput struct {
	GMPPaise        int64   `json:"gmp_paise" minimum:"-1000000000" maximum:"1000000000" doc:"GMP per share in paise; negative allowed"`
	Note            *string `json:"note,omitempty" minLength:"1" maxLength:"200"`
	CorrectsEntryID *string `json:"corrects_entry_id,omitempty" format:"uuid" doc:"The current entry this one corrects"`
}

// SubscriptionBody is the body of ipomarket-record-subscription (multiples are x100 integers).
type SubscriptionBody struct {
	AsOf         time.Time `json:"as_of"`
	TotalX100    int32     `json:"total_x100" minimum:"0" maximum:"10000000"`
	QIBX100      *int32    `json:"qib_x100,omitempty" minimum:"0" maximum:"10000000"`
	NIIX100      *int32    `json:"nii_x100,omitempty" minimum:"0" maximum:"10000000"`
	BNIIX100     *int32    `json:"bnii_x100,omitempty" minimum:"0" maximum:"10000000"`
	SNIIX100     *int32    `json:"snii_x100,omitempty" minimum:"0" maximum:"10000000"`
	RetailX100   *int32    `json:"retail_x100,omitempty" minimum:"0" maximum:"10000000"`
	EmployeeX100 *int32    `json:"employee_x100,omitempty" minimum:"0" maximum:"10000000"`
}

// CurrentGMP is the current GMP as clients and admins see it.
type CurrentGMP struct {
	GMPPaise            int64  `json:"gmp_paise"`
	ExpectedProfitPaise *int64 `json:"expected_profit_per_lot_paise" nullable:"true"`
	LotSize             *int32 `json:"lot_size" nullable:"true"`
	UpdatedAt           string `json:"updated_at" format:"date-time"`
}

// SubscriptionView is a subscription snapshot without author or source.
type SubscriptionView struct {
	AsOf         string `json:"as_of" format:"date-time"`
	TotalX100    int32  `json:"total_x100"`
	QIBX100      *int32 `json:"qib_x100" nullable:"true"`
	NIIX100      *int32 `json:"nii_x100" nullable:"true"`
	BNIIX100     *int32 `json:"bnii_x100" nullable:"true"`
	SNIIX100     *int32 `json:"snii_x100" nullable:"true"`
	RetailX100   *int32 `json:"retail_x100" nullable:"true"`
	EmployeeX100 *int32 `json:"employee_x100" nullable:"true"`
}

// TrendPointView is one effective GMP value over time.
type TrendPointView struct {
	GMPPaise            int64  `json:"gmp_paise"`
	ExpectedProfitPaise *int64 `json:"expected_profit_per_lot_paise" nullable:"true"`
	At                  string `json:"at" format:"date-time"`
}

// ActorView is the author of an admin entry.
type ActorView struct {
	Kind string  `json:"kind" enum:"admin,client,system"`
	ID   *string `json:"id" format:"uuid" nullable:"true"`
}

// AdminGMPEntry is one GMP entry in the admin history.
type AdminGMPEntry struct {
	ID                  string    `json:"id" format:"uuid"`
	GMPPaise            int64     `json:"gmp_paise"`
	ExpectedProfitPaise *int64    `json:"expected_profit_per_lot_paise" nullable:"true"`
	Note                *string   `json:"note" nullable:"true"`
	CorrectsEntryID     *string   `json:"corrects_entry_id" format:"uuid" nullable:"true"`
	CorrectedByEntryID  *string   `json:"corrected_by_entry_id" format:"uuid" nullable:"true"`
	Source              string    `json:"source" example:"manual"`
	Actor               ActorView `json:"actor"`
	RecordedAt          string    `json:"recorded_at" format:"date-time"`
}

// AdminSubscription is one snapshot in the admin history.
type AdminSubscription struct {
	ID string `json:"id" format:"uuid"`
	SubscriptionView
	Source     string    `json:"source" example:"manual"`
	Actor      ActorView `json:"actor"`
	RecordedAt string    `json:"recorded_at" format:"date-time"`
}

// warningBody is the wire form of Warning, registered as the schema "Warning" (the same shape 008
// registers; whichever module registers first wins).
type warningBody struct {
	Code   string           `json:"code" example:"ipomarket.gmp_exceeds_price"`
	Fields []string         `json:"fields"`
	Detail string           `json:"detail"`
	Params map[string]int64 `json:"params"`
}

// Schema registers the shared Warning schema.
func (warningBody) Schema(r huma.Registry) *huma.Schema {
	const name = "Warning"
	if _, ok := r.Map()[name]; !ok {
		r.Map()[name] = r.Schema(reflect.TypeOf(struct {
			Code   string           `json:"code" example:"ipo.min_application_out_of_range"`
			Fields []string         `json:"fields"`
			Detail string           `json:"detail"`
			Params map[string]int64 `json:"params"`
		}{}), false, name)
	}
	return &huma.Schema{Ref: "#/components/schemas/" + name}
}

// GMPRecordResult is the response of ipomarket-record-gmp.
type GMPRecordResult struct {
	Entry    AdminGMPEntry `json:"entry"`
	Current  CurrentGMP    `json:"current"`
	Warnings []warningBody `json:"warnings"`
}

// SubscriptionRecordResult is the response of ipomarket-record-subscription.
type SubscriptionRecordResult struct {
	Snapshot AdminSubscription `json:"snapshot"`
	Current  SubscriptionView  `json:"current"`
}

// AdminGMPPage is one page of the GMP history.
type AdminGMPPage struct {
	Items      []AdminGMPEntry `json:"items"`
	NextCursor *string         `json:"next_cursor" nullable:"true"`
}

// AdminSubscriptionPage is one page of the subscription history.
type AdminSubscriptionPage struct {
	Items      []AdminSubscription `json:"items"`
	NextCursor *string             `json:"next_cursor" nullable:"true"`
}

// ClientMarketView is the market view of one IPO.
type ClientMarketView struct {
	IPOID        string            `json:"ipo_id" format:"uuid"`
	CurrentGMP   *CurrentGMP       `json:"current_gmp"`
	Trend        []TrendPointView  `json:"trend"`
	Subscription *SubscriptionView `json:"subscription"`
}

// MarketSummary is the one-line market state of an IPO.
type MarketSummary struct {
	IPOID                 string      `json:"ipo_id" format:"uuid"`
	CurrentGMP            *CurrentGMP `json:"current_gmp"`
	SubscriptionTotalX100 *int32      `json:"subscription_total_x100" nullable:"true"`
	SubscriptionAsOf      *string     `json:"subscription_as_of" format:"date-time" nullable:"true"`
}

// MarketSummaries is the batch response.
type MarketSummaries struct {
	Items []MarketSummary `json:"items"`
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func cursorOut(next string) *string {
	if next == "" {
		return nil
	}
	return &next
}

func currentOut(c CurrentView) CurrentGMP {
	return CurrentGMP{GMPPaise: c.GMPPaise, ExpectedProfitPaise: c.ExpectedProfitPaise, LotSize: c.LotSize, UpdatedAt: rfc3339(c.UpdatedAt)}
}

func currentPtr(c *CurrentView) *CurrentGMP {
	if c == nil {
		return nil
	}
	o := currentOut(*c)
	return &o
}

func subViewOut(s Snapshot) SubscriptionView {
	return SubscriptionView{AsOf: rfc3339(s.AsOf), TotalX100: s.TotalX100, QIBX100: s.QIBX100, NIIX100: s.NIIX100,
		BNIIX100: s.BNIIX100, SNIIX100: s.SNIIX100, RetailX100: s.RetailX100, EmployeeX100: s.EmployeeX100}
}

func actorOut(kind string, id string, has bool) ActorView {
	a := ActorView{Kind: kind}
	if has {
		a.ID = &id
	}
	return a
}

func strPtr(p interface{ String() string }, ok bool) *string {
	if !ok {
		return nil
	}
	s := p.String()
	return &s
}

func gmpEntryOut(e GMPEntry) AdminGMPEntry {
	o := AdminGMPEntry{
		ID: e.ID.String(), GMPPaise: e.GMPPaise, ExpectedProfitPaise: e.ExpectedProfitPaise, Note: e.Note,
		Source: e.Source, RecordedAt: rfc3339(e.RecordedAt),
		Actor: actorOut(e.Actor.Kind, e.Actor.ID.String(), e.Actor.ID != uuid.Nil),
	}
	if e.CorrectsEntryID != nil {
		o.CorrectsEntryID = strPtr(e.CorrectsEntryID, true)
	}
	if e.CorrectedByEntryID != nil {
		o.CorrectedByEntryID = strPtr(e.CorrectedByEntryID, true)
	}
	return o
}

func adminSubOut(s Snapshot) AdminSubscription {
	return AdminSubscription{
		ID: s.ID.String(), SubscriptionView: subViewOut(s), Source: s.Source, RecordedAt: rfc3339(s.RecordedAt),
		Actor: actorOut(s.Actor.Kind, s.Actor.ID.String(), s.Actor.ID != uuid.Nil),
	}
}

func warningsOut(ws []Warning) []warningBody {
	out := make([]warningBody, 0, len(ws))
	for _, w := range ws {
		f := w.Fields
		if f == nil {
			f = []string{}
		}
		out = append(out, warningBody{Code: w.Code, Fields: f, Detail: w.Detail, Params: w.Params})
	}
	return out
}

func viewOut(v View) ClientMarketView {
	o := ClientMarketView{IPOID: v.IPOID.String(), CurrentGMP: currentPtr(v.CurrentGMP), Trend: make([]TrendPointView, 0, len(v.Trend))}
	for _, p := range v.Trend {
		o.Trend = append(o.Trend, TrendPointView{GMPPaise: p.GMPPaise, ExpectedProfitPaise: p.ExpectedProfitPaise, At: rfc3339(p.At)})
	}
	if v.Subscription != nil {
		sv := subViewOut(*v.Subscription)
		o.Subscription = &sv
	}
	return o
}

func summariesOut(ss []Summary) MarketSummaries {
	out := MarketSummaries{Items: make([]MarketSummary, 0, len(ss))}
	for _, s := range ss {
		m := MarketSummary{IPOID: s.IPOID.String(), CurrentGMP: currentPtr(s.CurrentGMP), SubscriptionTotalX100: s.SubscriptionTotalX100}
		if s.SubscriptionAsOf != nil {
			t := rfc3339(*s.SubscriptionAsOf)
			m.SubscriptionAsOf = &t
		}
		out.Items = append(out.Items, m)
	}
	return out
}

// nullableRef makes the property a "$ref or null" union (Huma refuses nullable on pointer-to-struct
// fields), so the generated TS client types it `| null`.
func nullableRef(s *huma.Schema, names ...string) *huma.Schema {
	for _, n := range names {
		p, ok := s.Properties[n]
		if !ok || p.Ref == "" {
			continue
		}
		s.Properties[n] = &huma.Schema{AnyOf: []*huma.Schema{{Ref: p.Ref}, {Type: "null"}}}
	}
	return s
}

// TransformSchema marks current_gmp and subscription nullable in OpenAPI.
func (ClientMarketView) TransformSchema(_ huma.Registry, s *huma.Schema) *huma.Schema {
	return nullableRef(s, "current_gmp", "subscription")
}

// TransformSchema marks current_gmp nullable in OpenAPI.
func (MarketSummary) TransformSchema(_ huma.Registry, s *huma.Schema) *huma.Schema {
	return nullableRef(s, "current_gmp")
}
