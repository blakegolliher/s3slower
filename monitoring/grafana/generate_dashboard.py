#!/usr/bin/env python3
"""Generate monitoring/grafana/dashboards/s3slower.json.

    python3 monitoring/grafana/generate_dashboard.py monitoring/grafana/dashboards/s3slower.json

Edit this file, not the JSON.

Charts group S3 operations into eight families with fixed, validated
colors (dark-surface steps of the reference categorical palette, in its
CVD-safe slot order); the per-operation table carries every individual
operation.
"""
import json
import sys

DS = {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}
F = 'instance=~"$instance", comm=~"$comm", s3_operation=~"$s3_operation", bucket=~"$bucket", endpoint=~"$endpoint"'
FS = 'instance=~"$instance", s3_operation=~"$s3_operation", bucket=~"$bucket"'
RI = "$__rate_interval"

# Operation families: (legend, s3_operation regex, color). Order = slot order.
FAMILIES = [
    ("GET", "GET_OBJECT", "#3987e5"),
    ("GET range", "GET_OBJECT_RANGE", "#d95926"),
    ("PUT", "PUT_OBJECT|COPY_OBJECT", "#199e70"),
    ("MPU part", "MPU_PART", "#c98500"),
    ("MPU control", "MPU_CREATE|MPU_COMPLETE|MPU_ABORT|MPU_LIST|MPU_LIST_PARTS", "#d55181"),
    ("LIST", "LIST_PREFIX|LIST_OBJECTS|LIST_BUCKETS", "#008300"),
    ("HEAD", "HEAD_OBJECT|HEAD_BUCKET", "#9085e9"),
    ("DELETE", "DELETE_OBJECT|DELETE_OBJECTS", "#e66767"),
]
OTHER_COLOR = "#8a8983"
ALL_FAMILY_RE = "|".join(f[1] for f in FAMILIES)
DATA_FAMILIES = FAMILIES[:4]
META_FAMILIES = FAMILIES[4:]

# Reserved status colors (never used for series identity).
GOOD, WARNING, SERIOUS, CRITICAL, NEUTRAL = "#0ca30c", "#fab219", "#ec835a", "#d03b3b", "#8a8983"

# Known clients get fixed colors (the eight palette slots, in order); anything
# else falls back to the theme palette.
CLIENT_COLORS = {"boto3": "#3987e5", "awscli": "#d95926", "elbencho": "#199e70",
                 "train-loader": "#c98500", "mc": "#d55181", "s5cmd": "#008300",
                 "rclone": "#9085e9", "curl": "#e66767"}

_next_id = [0]


def nid():
    _next_id[0] += 1
    return _next_id[0]


def fam_sel(regex, negate=False):
    return f's3_operation{"!~" if negate else "=~"}"{regex}"'


def target(expr, legend="", ref="A", instant=False, fmt="time_series", hide=False):
    t = {"datasource": DS, "expr": expr, "legendFormat": legend, "refId": ref,
         "range": not instant, "instant": instant, "format": fmt}
    if hide:
        t["hide"] = True
    return t


def refs():
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        yield c


def color_override(name, color, regex=False):
    return {"matcher": {"id": "byRegexp" if regex else "byName", "options": name},
            "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": color}}]}


def row(title, y):
    return {"type": "row", "title": title, "collapsed": False, "id": nid(),
            "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}, "panels": []}


def timeseries(title, targets, grid, unit, desc="", stack=False, log=False,
               overrides=None, fill=None, legend_calcs=("mean", "max", "lastNotNull"),
               no_value=None, min0=True):
    custom = {
        "drawStyle": "line", "lineWidth": 2, "lineInterpolation": "smooth",
        "fillOpacity": fill if fill is not None else (55 if stack else 0),
        "gradientMode": "none", "showPoints": "never", "spanNulls": True,
        "stacking": {"mode": "normal" if stack else "none", "group": "A"},
        "axisBorderShow": False, "axisPlacement": "auto",
        "scaleDistribution": {"type": "log", "log": 10} if log else {"type": "linear"},
        "thresholdsStyle": {"mode": "off"},
    }
    defaults = {"unit": unit, "custom": custom, "color": {"mode": "palette-classic"}}
    if min0 and not log:
        defaults["min"] = 0
    if no_value:
        defaults["noValue"] = no_value
    return {
        "type": "timeseries", "title": title, "description": desc, "id": nid(),
        "datasource": DS, "gridPos": grid, "targets": targets,
        "fieldConfig": {"defaults": defaults, "overrides": overrides or []},
        "options": {
            "legend": {"displayMode": "table", "placement": "right", "showLegend": True,
                       "calcs": list(legend_calcs)},
            "tooltip": {"mode": "multi", "sort": "desc"},
        },
    }


def stat(title, expr, grid, unit, desc="", color="#3987e5", status=None, no_value=None,
         instant=False, decimals=None, mappings=None, spark=True):
    defaults = {"unit": unit}
    if decimals is not None:
        defaults["decimals"] = decimals
    if no_value:
        defaults["noValue"] = no_value
    if mappings:
        defaults["mappings"] = mappings
    if status:
        defaults["color"] = {"mode": "thresholds"}
        defaults["thresholds"] = {"mode": "absolute", "steps": status}
        color_mode = "value"
    else:
        defaults["color"] = {"mode": "fixed", "fixedColor": color}
        color_mode = "none"
    return {
        "type": "stat", "title": title, "description": desc, "id": nid(),
        "datasource": DS, "gridPos": grid,
        "targets": [target(expr, instant=instant)],
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {"colorMode": color_mode, "graphMode": "area" if spark else "none",
                    "justifyMode": "auto", "orientation": "auto", "textMode": "value",
                    "wideLayout": True, "showPercentChange": False,
                    "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}},
    }


def family_targets(expr_fn, families, with_other=False, suffix=""):
    out, r = [], refs()
    for name, regex, _ in families:
        out.append(target(expr_fn(fam_sel(regex)), name + suffix, next(r)))
    if with_other:
        out.append(target(expr_fn(fam_sel(ALL_FAMILY_RE, negate=True)), "Other" + suffix, next(r)))
    return out


def family_overrides(families, with_other=False, suffix=""):
    ov = [color_override(name + suffix, color) for name, _, color in families]
    if with_other:
        ov.append(color_override("Other" + suffix, OTHER_COLOR))
    return ov


def q(p, sel):
    """histogram_quantile over the request-duration buckets."""
    return f"histogram_quantile({p}, sum by (le) (rate(s3slower_request_duration_ms_bucket{{{F}, {sel}}}[{RI}])))"


def build():
    panels = []
    y = 0

    # ---------------- Overview ----------------
    panels.append(row("Overview", y)); y += 1
    req_rate = f"sum(rate(s3slower_requests_total{{{F}}}[{RI}]))"
    tiles = [
        stat("Requests / s", req_rate, None, "reqps",
             "All S3 requests seen from this host, per second."),
        stat("Read throughput", f"sum(rate(s3slower_response_bytes_total{{{F}}}[{RI}]))", None, "Bps",
             "Response payload bytes per second (object data downloaded)."),
        stat("Write throughput", f"sum(rate(s3slower_request_bytes_total{{{F}}}[{RI}]))", None, "Bps",
             "Request payload bytes per second (object data uploaded)."),
        stat("GET p50 (TTFB)", q(0.5, fam_sel("GET_OBJECT|GET_OBJECT_RANGE")), None, "ms",
             "Median time to first byte for full and ranged GETs.", no_value="–"),
        stat("GET p99 (TTFB)", q(0.99, fam_sel("GET_OBJECT|GET_OBJECT_RANGE")), None, "ms",
             "99th percentile time to first byte for full and ranged GETs.", no_value="–"),
        stat("PUT / part p99", q(0.99, fam_sel("PUT_OBJECT|MPU_PART")), None, "ms",
             "99th percentile latency of PUTs and multipart parts, including the upload itself.",
             no_value="–"),
        stat("Error rate", f"(sum(rate(s3slower_request_errors_total{{{F}}}[{RI}])) or vector(0)) / {req_rate}",
             None, "percentunit", "Share of requests answered with HTTP 4xx/5xx.",
             status=[{"color": GOOD, "value": None}, {"color": WARNING, "value": 0.01},
                     {"color": CRITICAL, "value": 0.05}], no_value="–", decimals=2),
        stat("Events dropped", f'sum(increase(s3slower_events_dropped_total{{instance=~"$instance"}}[$__range])) or vector(0)',
             None, "short", "Events lost before export in the selected time range. 0 means every request was captured.",
             status=[{"color": GOOD, "value": None}, {"color": CRITICAL, "value": 1}], instant=True,
             decimals=0, spark=False),
    ]
    for i, t in enumerate(tiles):
        t["gridPos"] = {"h": 4, "w": 3, "x": 3 * i, "y": y}
        panels.append(t)
    y += 4

    # ---------------- Workload mix ----------------
    panels.append(row("Workload mix", y)); y += 1
    panels.append(timeseries(
        "Requests / s by operation",
        family_targets(lambda s: f"sum(rate(s3slower_requests_total{{{F}, {s}}}[{RI}]))", FAMILIES, True),
        {"h": 9, "w": 16, "x": 0, "y": y}, "reqps",
        "Request rate by operation family. MPU control = create/complete/abort/list; the table below breaks out every operation.",
        stack=True, overrides=family_overrides(FAMILIES, True)))
    bar_targets = family_targets(
        lambda s: f"sum(increase(s3slower_requests_total{{{F}, {s}}}[$__range]))", FAMILIES, True)
    for t in bar_targets:
        t["instant"], t["range"] = True, False
    panels.append({
        "type": "bargauge", "title": "Requests in range by operation", "id": nid(),
        "description": "Total requests per operation family over the selected time range.",
        "datasource": DS, "gridPos": {"h": 9, "w": 8, "x": 16, "y": y}, "targets": bar_targets,
        "fieldConfig": {"defaults": {"unit": "none", "decimals": 0, "min": 0,
                                     "color": {"mode": "palette-classic"}},
                        "overrides": family_overrides(FAMILIES, True)},
        "options": {"displayMode": "basic", "orientation": "horizontal", "showUnfilled": True,
                    "valueMode": "text", "namePlacement": "left", "sizing": "auto",
                    "minVizHeight": 16, "maxVizHeight": 24,
                    "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}},
    })
    y += 9
    panels.append(timeseries(
        "Read throughput by operation",
        family_targets(lambda s: f"sum(rate(s3slower_response_bytes_total{{{F}, {s}}}[{RI}])) > 1024", FAMILIES, True),
        {"h": 8, "w": 12, "x": 0, "y": y}, "Bps",
        "Response payload bytes per second (data downloaded), by operation family. Families under 1 KB/s are hidden.",
        stack=True, overrides=family_overrides(FAMILIES, True)))
    panels.append(timeseries(
        "Write throughput by operation",
        family_targets(lambda s: f"sum(rate(s3slower_request_bytes_total{{{F}, {s}}}[{RI}])) > 1024", FAMILIES, True),
        {"h": 8, "w": 12, "x": 12, "y": y}, "Bps",
        "Request payload bytes per second (data uploaded), by operation family. Families under 1 KB/s are hidden.",
        stack=True, overrides=family_overrides(FAMILIES, True)))
    y += 8

    # ---------------- Latency ----------------
    panels.append(row("Latency", y)); y += 1
    dp_targets, r = [], refs()
    for name, regex, _ in DATA_FAMILIES:
        dp_targets.append(target(q(0.99, fam_sel(regex)), f"{name} p99", next(r)))
        dp_targets.append(target(q(0.5, fam_sel(regex)), f"{name} p50", next(r)))
    dp_over = []
    for name, _, color in DATA_FAMILIES:
        dp_over.append(color_override(f"{name} p99", color))
        dp_over.append({"matcher": {"id": "byName", "options": f"{name} p50"},
                        "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": color}},
                                       {"id": "custom.lineStyle", "value": {"fill": "dash", "dash": [6, 4]}},
                                       {"id": "custom.lineWidth", "value": 1}]})
    panels.append(timeseries(
        "Data-path latency (p99 solid, p50 dashed)", dp_targets,
        {"h": 9, "w": 12, "x": 0, "y": y}, "ms",
        "GET latency is time to first byte. PUT and MPU part latency runs from the request "
        "head to the response, so it includes uploading the body. Log scale.",
        log=True, overrides=dp_over, legend_calcs=("mean", "max")))
    panels.append(timeseries(
        "Metadata latency (p99)",
        family_targets(lambda s: q(0.99, s), META_FAMILIES, True, " p99"),
        {"h": 9, "w": 12, "x": 12, "y": y}, "ms",
        "99th percentile latency of metadata operations. DELETE includes batch DeleteObjects. Log scale.",
        log=True, overrides=family_overrides(META_FAMILIES, True, " p99"), legend_calcs=("mean", "max")))
    y += 9
    panels.append({
        "type": "heatmap", "title": "Latency distribution (all requests)", "id": nid(),
        "description": "Requests per latency bucket over time. Brighter cells hold more requests.",
        "datasource": DS, "gridPos": {"h": 8, "w": 24, "x": 0, "y": y},
        "targets": [target(f"sum by (le) (increase(s3slower_request_duration_ms_bucket{{{F}}}[{RI}]))",
                           "{{le}}", fmt="heatmap")],
        "fieldConfig": {"defaults": {"custom": {"scaleDistribution": {"type": "linear"},
                                                "hideFrom": {"legend": False, "tooltip": False, "viz": False}}},
                        "overrides": []},
        "options": {
            "calculate": False, "cellGap": 1, "yAxis": {"axisPlacement": "left", "unit": "ms"},
            "rowsFrame": {"layout": "auto"},
            "color": {"mode": "opacity", "fill": "#3987e5", "scale": "exponential", "exponent": 0.5,
                      "steps": 64, "reverse": False},
            "cellValues": {"unit": "short"}, "filterValues": {"le": 1e-9},
            "legend": {"show": True}, "showValue": "never",
            "tooltip": {"mode": "single", "yHistogram": True, "showColorScale": True},
            "exemplars": {"color": "rgba(255,0,255,0.7)"},
        },
    })
    y += 8

    # ---------------- Per-operation table ----------------
    panels.append(row("Per-operation detail", y)); y += 1
    by = "sum by (s3_operation)"
    inc = lambda m: f"{by} (increase({m}{{{F}}}[$__range]))"
    tbl = [
        (f"{inc('s3slower_requests_total')}", "Requests"),
        (f"{by} (rate(s3slower_requests_total{{{F}}}[$__range]))", "Req/s"),
        (f"({inc('s3slower_request_bytes_total')} + {inc('s3slower_response_bytes_total')}) / {inc('s3slower_requests_total')}", "Avg payload"),
        (f"{by} (rate(s3slower_request_bytes_total{{{F}}}[$__range])) + {by} (rate(s3slower_response_bytes_total{{{F}}}[$__range]))", "Throughput"),
        (f"histogram_quantile(0.5, sum by (le, s3_operation) (rate(s3slower_request_duration_ms_bucket{{{F}}}[$__range])))", "p50"),
        (f"histogram_quantile(0.99, sum by (le, s3_operation) (rate(s3slower_request_duration_ms_bucket{{{F}}}[$__range])))", "p99"),
        (f"{inc('s3slower_request_errors_total')} or (0 * {inc('s3slower_requests_total')})", "Errors"),
    ]
    tbl_targets, rename, r = [], {}, refs()
    for expr, col in tbl:
        ref = next(r)
        tbl_targets.append(target(expr, "", ref, instant=True, fmt="table"))
        rename[f"Value #{ref}"] = col
    units = {"Requests": ("none", 0), "Req/s": ("reqps", 2), "Avg payload": ("bytes", 1),
             "Throughput": ("Bps", 1), "p50": ("ms", 2), "p99": ("ms", 2), "Errors": ("none", 0)}
    tbl_over = [{"matcher": {"id": "byName", "options": c},
                 "properties": [{"id": "unit", "value": u}, {"id": "decimals", "value": d}]}
                for c, (u, d) in units.items()]
    tbl_over.append({"matcher": {"id": "byName", "options": "Errors"},
                     "properties": [{"id": "custom.cellOptions", "value": {"type": "color-text"}},
                                    {"id": "color", "value": {"mode": "thresholds"}},
                                    {"id": "thresholds", "value": {"mode": "absolute", "steps": [
                                        {"color": "text", "value": None}, {"color": CRITICAL, "value": 1}]}}]})
    tbl_over.append({"matcher": {"id": "byName", "options": "Operation"},
                     "properties": [{"id": "custom.width", "value": 200}]})
    panels.append({
        "type": "table", "title": "Per-operation summary (selected time range)", "id": nid(),
        "description": "Every S3 operation individually. GET latency is time to first byte; "
                       "PUT/part latency includes the upload. Avg payload is body bytes per request.",
        "datasource": DS, "gridPos": {"h": 13, "w": 24, "x": 0, "y": y}, "targets": tbl_targets,
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"},
                                                "inspect": False}},
                        "overrides": tbl_over},
        "options": {"showHeader": True, "cellHeight": "sm",
                    "sortBy": [{"displayName": "Requests", "desc": True}],
                    "footer": {"show": False, "reducer": ["sum"], "fields": ""}},
        "transformations": [
            {"id": "merge", "options": {}},
            {"id": "organize", "options": {
                "excludeByName": {"Time": True},
                "indexByName": {"s3_operation": 0, **{c: i + 1 for i, (_, c) in enumerate(tbl)}},
                "renameByName": {"s3_operation": "Operation", **rename}}},
        ],
    })
    y += 13

    # ---------------- Clients ----------------
    panels.append(row("Clients", y)); y += 1
    client_over = [color_override(c, col) for c, col in CLIENT_COLORS.items()]
    panels.append(timeseries(
        "Requests / s by client",
        [target(f"sum by (comm) (rate(s3slower_requests_total{{{F}}}[{RI}]))", "{{comm}}")],
        {"h": 8, "w": 8, "x": 0, "y": y}, "reqps",
        "Client = well-known tool (awscli, boto3, elbencho, ...) or the process name.",
        overrides=client_over, legend_calcs=("mean", "lastNotNull")))
    panels.append(timeseries(
        "p99 latency by client",
        [target(f"histogram_quantile(0.99, sum by (le, comm) (rate(s3slower_request_duration_ms_bucket{{{F}}}[{RI}])))", "{{comm}}")],
        {"h": 8, "w": 8, "x": 8, "y": y}, "ms",
        "Across all operations, so a client doing large uploads reads higher. Log scale.",
        log=True, overrides=client_over, legend_calcs=("mean", "max")))
    panels.append(timeseries(
        "Throughput by client",
        [target(f"sum by (comm) (rate(s3slower_request_bytes_total{{{F}}}[{RI}])) + sum by (comm) (rate(s3slower_response_bytes_total{{{F}}}[{RI}]))", "{{comm}}")],
        {"h": 8, "w": 8, "x": 16, "y": y}, "Bps",
        "Upload + download payload bytes per second.",
        overrides=client_over, legend_calcs=("mean", "lastNotNull")))
    y += 8

    # ---------------- Errors & status ----------------
    panels.append(row("Errors & HTTP status", y)); y += 1
    status_targets, r = [], refs()
    for cls, rx in (("2xx", "2.."), ("3xx", "3.."), ("4xx", "4.."), ("5xx", "5..")):
        status_targets.append(target(
            f'sum(rate(s3slower_response_status_total{{{FS}, status_code=~"{rx}"}}[{RI}])) > 0', cls, next(r)))
    panels.append(timeseries(
        "Responses / s by status class", status_targets,
        {"h": 8, "w": 12, "x": 0, "y": y}, "reqps", "HTTP responses per second, grouped by status class.",
        stack=True, overrides=[color_override("2xx", GOOD), color_override("3xx", NEUTRAL),
                               color_override("4xx", SERIOUS), color_override("5xx", CRITICAL)],
        legend_calcs=("mean", "max")))
    panels.append(timeseries(
        "Errors / s by operation and status",
        [target(f'sum by (s3_operation, status_code) (rate(s3slower_response_status_total{{{FS}, status_code=~"[45].."}}[{RI}])) > 0',
                "{{s3_operation}} {{status_code}}")],
        {"h": 8, "w": 12, "x": 12, "y": y}, "reqps",
        "4xx/5xx responses by operation, e.g. 404 on HEAD (missing key) or 503 SlowDown.",
        legend_calcs=("mean", "max"), no_value="No errors"))
    y += 8

    # ---------------- Tracer health ----------------
    panels.append(row("Tracer health", y)); y += 1
    up = stat("Exporter", 'min(up{job="s3slower", instance=~"$instance"})', {"h": 5, "w": 4, "x": 0, "y": y}, "none",
              "Whether Prometheus can scrape s3slower.",
              status=[{"color": CRITICAL, "value": None}, {"color": GOOD, "value": 1}],
              mappings=[{"type": "value", "options": {"0": {"text": "DOWN", "index": 0},
                                                      "1": {"text": "UP", "index": 1}}}],
              spark=False)
    up["options"]["colorMode"] = "background"
    panels.append(up)
    panels.append(timeseries(
        "Dropped events / s by reason",
        [target(f'sum by (reason) (rate(s3slower_events_dropped_total{{instance=~"$instance"}}[{RI}]))', "{{reason}}")],
        {"h": 5, "w": 20, "x": 4, "y": y}, "short",
        "perf_lost: kernel ring overflow (raise --perf-buffer-kb). channel_full: userspace back-pressure.",
        overrides=[color_override("perf_lost", CRITICAL), color_override("channel_full", SERIOUS)],
        no_value="No drops", legend_calcs=("max", "lastNotNull")))
    y += 5
    return panels


def var(name, label, query, hide=0):
    return {
        "name": name, "label": label, "type": "query", "datasource": DS,
        "definition": query, "query": {"qryType": 1, "query": query, "refId": "PrometheusVariableQueryEditor-VariableQuery"},
        "refresh": 2, "regex": "", "sort": 1, "multi": True, "includeAll": True, "allValue": ".*",
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]}, "options": [],
        "hide": hide, "skipUrlSync": False,
    }


def main(out):
    dash = {
        "__inputs": [{"name": "DS_PROMETHEUS", "label": "Prometheus", "description": "", "type": "datasource",
                      "pluginId": "prometheus", "pluginName": "Prometheus"}],
        "__requires": [{"type": "grafana", "id": "grafana", "name": "Grafana", "version": "10.4.1"},
                       {"type": "datasource", "id": "prometheus", "name": "Prometheus", "version": "1.0.0"},
                       {"type": "panel", "id": "timeseries", "name": "Time series", "version": ""},
                       {"type": "panel", "id": "stat", "name": "Stat", "version": ""},
                       {"type": "panel", "id": "table", "name": "Table", "version": ""},
                       {"type": "panel", "id": "bargauge", "name": "Bar gauge", "version": ""},
                       {"type": "panel", "id": "heatmap", "name": "Heatmap", "version": ""}],
        "annotations": {"list": [{"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
                                  "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
                                  "name": "Annotations & Alerts", "type": "dashboard"}]},
        "editable": True, "fiscalYearStartMonth": 0, "graphTooltip": 1, "id": None, "links": [],
        "panels": build(),
        "refresh": "5s", "schemaVersion": 39, "tags": ["s3slower", "s3", "ebpf", "latency"],
        "templating": {"list": [
            {"current": {"selected": False, "text": "Prometheus", "value": "Prometheus"}, "hide": 0,
             "includeAll": False, "label": "Datasource", "name": "DS_PROMETHEUS", "options": [],
             "query": "prometheus", "refresh": 1, "regex": "", "skipUrlSync": False, "type": "datasource"},
            var("instance", "Host", "label_values(s3slower_requests_total, instance)"),
            var("comm", "Client", 'label_values(s3slower_requests_total{instance=~"$instance"}, comm)'),
            var("s3_operation", "Operation", 'label_values(s3slower_requests_total{instance=~"$instance"}, s3_operation)'),
            var("bucket", "Bucket (opt-in label)", 'label_values(s3slower_requests_total{instance=~"$instance"}, bucket)'),
            var("endpoint", "Endpoint (opt-in label)", 'label_values(s3slower_requests_total{instance=~"$instance"}, endpoint)'),
        ]},
        "time": {"from": "now-15m", "to": "now"},
        "timepicker": {"refresh_intervals": ["5s", "10s", "30s", "1m", "5m"]},
        "timezone": "browser", "title": "S3Slower - S3 Client Latency Monitor", "uid": "s3slower-main",
        "version": 2, "weekStart": "",
    }
    with open(out, "w") as f:
        json.dump(dash, f, indent=2)
        f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1])
