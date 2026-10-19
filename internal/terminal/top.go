package terminal

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/s3slower/s3slower/internal/event"
)

// topWindow is how many completed seconds the top view aggregates over.
// One more slot holds the second in progress.
const topWindow = 5

// maxSamplesPerSlot bounds the latency samples kept per key per second so
// a very busy host cannot grow the view's memory without limit.
const maxSamplesPerSlot = 20000

// agg accumulates requests for one key (operation or client) in one slot.
type agg struct {
	n, errs   int
	req, resp uint64
	lat       []float64
}

func (a *agg) add(e *event.S3Event) {
	a.n++
	if e.IsError {
		a.errs++
	}
	a.req += uint64(e.RequestSize)
	a.resp += uint64(e.ResponseSize)
	if len(a.lat) < maxSamplesPerSlot {
		a.lat = append(a.lat, e.LatencyMs)
	}
}

func (a *agg) merge(b *agg) {
	a.n += b.n
	a.errs += b.errs
	a.req += b.req
	a.resp += b.resp
	a.lat = append(a.lat, b.lat...)
}

type slot struct {
	ops, clients map[string]*agg
}

func newSlot() slot {
	return slot{ops: map[string]*agg{}, clients: map[string]*agg{}}
}

// topView aggregates events into a sliding window and renders a
// refreshing per-operation / per-client summary.
type topView struct {
	mu     sync.Mutex
	slots  [topWindow + 1]slot
	cur    int
	filled int // slots completed so far, up to topWindow
	totals map[string]uint64
	start  time.Time
}

func newTopView() *topView {
	t := &topView{totals: map[string]uint64{}, start: time.Now()}
	for i := range t.slots {
		t.slots[i] = newSlot()
	}
	return t
}

func (t *topView) add(e *event.S3Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.slots[t.cur]
	op := string(e.Operation)
	client := e.ClientType
	if client == "" {
		client = e.Comm
	}
	addTo(s.ops, op, e)
	addTo(s.clients, client, e)
	t.totals[op]++
}

func addTo(m map[string]*agg, key string, e *event.S3Event) {
	a := m[key]
	if a == nil {
		a = &agg{}
		m[key] = a
	}
	a.add(e)
}

// tick closes the current one-second slot and starts a new one.
func (t *topView) tick() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cur = (t.cur + 1) % len(t.slots)
	t.slots[t.cur] = newSlot()
	if t.filled < topWindow {
		t.filled++
	}
}

type row struct {
	key string
	a   agg
}

// render returns the screen contents (without the clear sequence).
func (t *topView) render(now time.Time) string {
	t.mu.Lock()
	ops, clients := map[string]*agg{}, map[string]*agg{}
	for i, s := range t.slots {
		if i == t.cur {
			continue // partial second; excluded so rates stay honest
		}
		for k, a := range s.ops {
			if ops[k] == nil {
				ops[k] = &agg{}
			}
			ops[k].merge(a)
		}
		for k, a := range s.clients {
			if clients[k] == nil {
				clients[k] = &agg{}
			}
			clients[k].merge(a)
		}
	}
	totals := make(map[string]uint64, len(t.totals))
	for k, v := range t.totals {
		totals[k] = v
	}
	secs := float64(t.filled)
	t.mu.Unlock()
	if secs == 0 {
		secs = 1
	}

	var all agg
	for _, a := range ops {
		all.n += a.n
		all.errs += a.errs
		all.req += a.req
		all.resp += a.resp
	}

	var b strings.Builder
	errPct := 0.0
	if all.n > 0 {
		errPct = 100 * float64(all.errs) / float64(all.n)
	}
	fmt.Fprintf(&b, "s3slower top  %s  (last %.0fs)   %.1f req/s   read %s/s   write %s/s   errors %.1f%%\n\n",
		now.Format("15:04:05"), secs, float64(all.n)/secs, humanBytes(float64(all.resp)/secs),
		humanBytes(float64(all.req)/secs), errPct)

	writeTable(&b, "OPERATION", sortRows(ops), secs, totals)
	b.WriteString("\n")
	writeTable(&b, "CLIENT", sortRows(clients), secs, nil)
	b.WriteString("\nGET latency = time to first byte; PUT/part latency includes the upload.  Ctrl-C to quit.\n")
	return b.String()
}

func sortRows(m map[string]*agg) []row {
	rows := make([]row, 0, len(m))
	for k, a := range m {
		rows = append(rows, row{k, *a})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].a.n != rows[j].a.n {
			return rows[i].a.n > rows[j].a.n
		}
		return rows[i].key < rows[j].key
	})
	return rows
}

func writeTable(b *strings.Builder, title string, rows []row, secs float64, totals map[string]uint64) {
	fmt.Fprintf(b, "%-18s %8s %10s %10s %9s %9s %9s %9s %6s", title,
		"REQ/S", "READ/S", "WRITE/S", "AVG SIZE", "P50 ms", "P99 ms", "MAX ms", "ERR%")
	if totals != nil {
		fmt.Fprintf(b, " %9s", "TOTAL")
	}
	b.WriteString("\n")
	for _, r := range rows {
		a := r.a
		sort.Float64s(a.lat)
		avg := 0.0
		if a.n > 0 {
			avg = float64(a.req+a.resp) / float64(a.n)
		}
		fmt.Fprintf(b, "%-18s %8.1f %10s %10s %9s %9.2f %9.2f %9.2f %6.1f",
			truncateRight(r.key, 18), float64(a.n)/secs,
			humanBytes(float64(a.resp)/secs), humanBytes(float64(a.req)/secs), humanBytes(avg),
			quantile(a.lat, 0.5), quantile(a.lat, 0.99), quantile(a.lat, 1),
			100*float64(a.errs)/float64(max(a.n, 1)))
		if totals != nil {
			fmt.Fprintf(b, " %9d", totals[r.key])
		}
		b.WriteString("\n")
	}
	if len(rows) == 0 {
		b.WriteString("  (no requests in window)\n")
	}
}

// quantile returns the q-quantile of sorted values (nearest rank).
func quantile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(q * float64(len(sorted)))
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

// humanBytes formats a byte count with SI units.
func humanBytes(v float64) string {
	units := []string{"B", "kB", "MB", "GB", "TB"}
	i := 0
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f%s", v, units[i])
	}
	return fmt.Sprintf("%.1f%s", v, units[i])
}

// run redraws the view every second until stop is closed.
func (t *topView) run(out io.Writer, stop <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			t.tick()
			// Home the cursor, clear the screen, draw.
			fmt.Fprint(out, "\x1b[H\x1b[2J"+t.render(now))
		}
	}
}
