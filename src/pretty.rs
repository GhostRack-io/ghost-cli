//! Command results for reading on a terminal, in the style of the install
//! output: a two-column margin, `==>`
//! headings in the bright-magenta accent, bold labels padded so the values
//! line up, green, yellow and red for states, and dim for what is absent.
//! Colors are written only when the stream is a terminal whose `TERM` is set
//! and not "dumb", and a non-empty `NO_COLOR` turns them off (no-color.org).
//!
//! The result is for reading, not for parsing. A number whose name carries a
//! unit is shown in that unit and labelled without it, a timestamp loses its
//! fraction, the fields that identify and describe a record come first, and
//! a list whose rows fit the terminal is a table. Nothing here is
//! JSON-escaped, so every server-supplied string goes through
//! [`escape_control`]; a text of several lines, such as a ticket message,
//! keeps its lines, each escaped on its own. Scripts ask for `--json`.

use std::{fmt::Write as _, io::IsTerminal};

use chrono::{DateTime, Utc};
use gigahost_client_api::hypervisor::{CpuTier, size_cpu_text};
use serde::Deserialize as _;
use serde_json::{Map, Number, Value};

use crate::escape_control;

/// Where a result's labels start.
const MARGIN: usize = 2;
/// Where the text below a `==>` heading starts: under the heading's title.
const SECTION_INDENT: usize = 6;
/// Labels are padded to at least this width, as in the install scripts.
const LABEL_WIDTH: usize = 12;
/// A label longer than this no longer moves the values of its block.
const MAXIMUM_LABEL_WIDTH: usize = 48;
const COLUMN_GAP: usize = 2;
/// The width of a terminal that does not tell its own.
const DEFAULT_WIDTH: usize = 80;
const NARROWEST_WIDTH: usize = 40;

const BINARY_UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
const BIT_RATE_UNITS: [&str; 5] = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"];

/// The install scripts' palette. Bright magenta (95) stays readable on dark
/// and light backgrounds alike, where plain magenta does not.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Paint {
    Accent,
    Good,
    Bad,
    Warn,
    Bold,
    Dim,
}

impl Paint {
    const fn code(self) -> &'static str {
        match self {
            Self::Accent => "1;95",
            Self::Good => "32",
            Self::Bad => "1;31",
            Self::Warn => "33",
            Self::Bold => "1",
            Self::Dim => "2",
        }
    }
}

/// What the stream a result is written to can show.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Terminal {
    /// Whether ANSI colors are written.
    pub colors: bool,
    /// The columns a table may take before its rows are shown as blocks.
    pub width: usize,
}

impl Terminal {
    /// Standard output as it is now.
    #[must_use]
    pub fn stdout() -> Self {
        let stream = std::io::stdout();
        Self::of(stream.is_terminal(), || window_columns(&stream))
    }

    /// Standard error as it is now.
    #[must_use]
    pub fn stderr() -> Self {
        let stream = std::io::stderr();
        Self::of(stream.is_terminal(), || window_columns(&stream))
    }

    /// A pipe or a file: no colors, and no width to fit, so a list stays
    /// one row per line for `grep` and friends.
    #[must_use]
    pub const fn plain() -> Self {
        Self {
            colors: false,
            width: usize::MAX,
        }
    }

    fn of(terminal: bool, window: impl FnOnce() -> Option<usize>) -> Self {
        if !terminal {
            return Self::plain();
        }
        let term = std::env::var("TERM").unwrap_or_default();
        let colors = !term.is_empty()
            && term != "dumb"
            && std::env::var_os("NO_COLOR").is_none_or(|value| value.is_empty());
        let exported = || {
            std::env::var("COLUMNS")
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
        };
        let width = window()
            .or_else(exported)
            .filter(|&width| width >= NARROWEST_WIDTH)
            .unwrap_or(DEFAULT_WIDTH);
        Self { colors, width }
    }
}

#[cfg(unix)]
fn window_columns(stream: &impl std::os::fd::AsFd) -> Option<usize> {
    rustix::termios::tcgetwinsize(stream)
        .ok()
        .map(|size| usize::from(size.ws_col))
        .filter(|&columns| columns > 0)
}

#[cfg(not(unix))]
fn window_columns<S>(_stream: &S) -> Option<usize> {
    None
}

/// One piece of a line: its characters, which count towards widths, and
/// the paint they get on a terminal with colors.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Text {
    plain: String,
    paint: Option<Paint>,
}

impl Text {
    fn plain(text: impl Into<String>) -> Self {
        Self {
            plain: text.into(),
            paint: None,
        }
    }

    fn painted(text: impl Into<String>, paint: Paint) -> Self {
        Self {
            plain: text.into(),
            paint: Some(paint),
        }
    }

    /// Something that is not there: no value, or an empty list.
    fn absent(text: &str) -> Self {
        Self::painted(text, Paint::Dim)
    }

    fn width(&self) -> usize {
        self.plain.chars().count()
    }

    fn write(&self, line: &mut String, colors: bool) {
        match self.paint {
            Some(paint) if colors && !self.plain.is_empty() => {
                let _ = write!(line, "\x1b[{}m{}\x1b[0m", paint.code(), self.plain);
            }
            _ => line.push_str(&self.plain),
        }
    }
}

/// `text` in the paint of the state `state` on a stream with `colors`.
pub(crate) fn paint_state(state: &str, text: &str, colors: bool) -> String {
    let mut line = String::new();
    Text {
        plain: text.to_owned(),
        paint: state_paint(state),
    }
    .write(&mut line, colors);
    line
}

/// `text` in bold on a stream with `colors`.
pub(crate) fn paint_bold(text: &str, colors: bool) -> String {
    let mut line = String::new();
    Text::painted(text, Paint::Bold).write(&mut line, colors);
    line
}

/// `text` as the heading of a failure on a stream with `colors`.
pub(crate) fn paint_failure(text: &str, colors: bool) -> String {
    let mut line = String::new();
    Text::painted(text, Paint::Bad).write(&mut line, colors);
    line
}

/// Format a command result for reading on `terminal`.
#[must_use]
pub fn render(value: &Value, terminal: Terminal) -> String {
    let mut page = Page {
        terminal,
        lines: Vec::new(),
    };
    let mut value = value.clone();
    name_size_cpus(&mut value);
    name_bandwidths(&mut value);
    match &value {
        Value::Object(map) if !map.is_empty() => page.document(map),
        Value::Array(items) if !items.is_empty() => page.collection(items, MARGIN, SECTION_INDENT),
        scalar => {
            let text = inline(None, scalar).unwrap_or_else(|| Text::absent("none"));
            page.line(&" ".repeat(MARGIN), &[text]);
        }
    }
    page.lines.join("\n")
}

/// The rows of a list for reading, with their `columns` in that order
/// rather than ranked: a table when it fits `terminal`, else a block per
/// row, and then the page's `next_cursor`, when there is a next page.
#[must_use]
pub(crate) fn render_rows(
    columns: &[&str],
    rows: &[Value],
    next_cursor: Option<&str>,
    terminal: Terminal,
) -> String {
    let mut page = Page {
        terminal,
        lines: Vec::new(),
    };
    page.rows(columns, rows, MARGIN, SECTION_INDENT);
    if let Some(cursor) = next_cursor {
        page.blank();
        let (key, value) = ("next_cursor".to_owned(), Value::from(cursor));
        page.fields(&[(&key, &value)], MARGIN, false);
    }
    page.lines.join("\n")
}

/// A part of a result shown under a `==>` heading of its own, in the
/// order it is given rather than ranked.
pub(crate) enum Section {
    /// Label and value lines.
    Fields(Vec<(&'static str, Value)>),
    /// The rows of a list with these columns, as [`render_rows`] shows them.
    Rows(Vec<&'static str>, Vec<Value>),
}

/// A record for reading as [`render`] shows it, followed by `sections`.
#[must_use]
pub(crate) fn render_sections(
    map: &Map<String, Value>,
    sections: &[(&str, Section)],
    terminal: Terminal,
) -> String {
    let mut page = Page {
        terminal,
        lines: Vec::new(),
    };
    let mut record = Value::Object(map.clone());
    name_size_cpus(&mut record);
    if let Value::Object(map) = &record {
        page.document(map);
    }
    for (title, section) in sections {
        page.heading(title);
        match section {
            Section::Fields(fields) => {
                let keys: Vec<String> = fields.iter().map(|(key, _)| (*key).to_owned()).collect();
                let fields: Vec<(&String, &Value)> = keys
                    .iter()
                    .zip(fields.iter().map(|(_, value)| value))
                    .collect();
                page.fields(&fields, SECTION_INDENT, false);
            }
            Section::Rows(columns, rows) => {
                page.rows(columns, rows, SECTION_INDENT, SECTION_INDENT);
            }
        }
    }
    page.lines.join("\n")
}

struct Page {
    terminal: Terminal,
    lines: Vec<String>,
}

impl Page {
    /// One line: `start`, then the pieces one after another.
    fn line(&mut self, start: &str, pieces: &[Text]) {
        let mut line = start.to_owned();
        for piece in pieces {
            piece.write(&mut line, self.terminal.colors);
        }
        self.lines.push(line.trim_end().to_owned());
    }

    fn blank(&mut self) {
        if self.lines.last().is_some_and(|line| !line.is_empty()) {
            self.lines.push(String::new());
        }
    }

    /// The start of a line whose text begins at `indent`, behind the dim
    /// dash of a list item when it opens one.
    fn start(&self, indent: usize, item: bool) -> String {
        if !item {
            return " ".repeat(indent);
        }
        let mut start = " ".repeat(indent.saturating_sub(2));
        Text::absent("-").write(&mut start, self.terminal.colors);
        start.push(' ');
        start
    }

    /// The result of a command: its plain fields first, then a `==>`
    /// heading for every field that holds a record or a list.
    fn document(&mut self, map: &Map<String, Value>) {
        let (fields, sections): (Vec<_>, Vec<_>) = ordered(map)
            .into_iter()
            .partition(|(key, value)| inline(Some(key), value).is_some());
        self.fields(&fields, MARGIN, false);
        for (key, value) in sections {
            self.heading(key);
            self.nested(value, SECTION_INDENT, SECTION_INDENT, SECTION_INDENT);
        }
    }

    /// The `==>` heading of a section, after a blank line.
    fn heading(&mut self, title: &str) {
        self.blank();
        self.line(
            &" ".repeat(MARGIN),
            &[
                Text::painted("==>", Paint::Accent),
                Text::plain(" "),
                Text::painted(escape_control(title), Paint::Bold),
            ],
        );
    }

    /// The rows of a list with `columns` in that order: a table at
    /// `table_indent` when it fits the terminal, else a block per row with
    /// its text at `item_indent`.
    fn rows(&mut self, columns: &[&str], rows: &[Value], table_indent: usize, item_indent: usize) {
        let records: Vec<&Map<String, Value>> = rows.iter().filter_map(Value::as_object).collect();
        if records.is_empty() {
            self.line(&" ".repeat(table_indent), &[Text::absent("none")]);
        } else if !self.table_of(&records, columns, table_indent) {
            for (index, record) in records.iter().enumerate() {
                if index > 0 {
                    self.lines.push(String::new());
                }
                let fields: Vec<(&String, &Value)> = columns
                    .iter()
                    .filter_map(|column| record.get_key_value(*column))
                    .collect();
                self.fields(&fields, item_indent, true);
            }
        }
    }

    /// A record or a list below its label or heading: a record's labels
    /// start at `indent`, a table at `table_indent`, and the text of a
    /// list's items at `item_indent`.
    fn nested(&mut self, value: &Value, indent: usize, table_indent: usize, item_indent: usize) {
        match value {
            Value::Object(map) => self.fields(&ordered(map), indent, false),
            Value::Array(items) => self.collection(items, table_indent, item_indent),
            scalar => {
                let text = inline(None, scalar).unwrap_or_else(|| Text::absent("none"));
                self.line(&" ".repeat(indent), &[text]);
            }
        }
    }

    /// Label and value lines with the values in one column. A field that
    /// holds a record or a list comes after those, with it below its
    /// label, indented.
    fn fields(&mut self, fields: &[(&String, &Value)], indent: usize, item: bool) {
        let (plain, holding): (Vec<_>, Vec<_>) = fields
            .iter()
            .partition(|(key, value)| inline(Some(key), value).is_some());
        let fields: Vec<_> = plain.into_iter().chain(holding).collect();
        let names = labels(
            &fields
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
        );
        let label_width = fields
            .iter()
            .zip(&names)
            .filter(|((key, value), _)| inline(Some(key), value).is_some())
            .map(|(_, name)| escape_control(name).chars().count() + COLUMN_GAP)
            .filter(|&width| width <= MAXIMUM_LABEL_WIDTH)
            .max()
            .unwrap_or(0)
            .max(LABEL_WIDTH);
        for (index, ((key, value), name)) in fields.iter().zip(&names).enumerate() {
            let start = self.start(indent, item && index == 0);
            let label = Text::painted(escape_control(name), Paint::Bold);
            if let Some(text) = inline(Some(key), value) {
                let padding = label_width.saturating_sub(label.width()).max(COLUMN_GAP);
                let column = indent + label.width() + padding;
                let mut lines = text_lines(value).unwrap_or_default().into_iter();
                let text = lines.next().map_or(text, Text::plain);
                self.line(&start, &[label, Text::plain(" ".repeat(padding)), text]);
                for line in lines {
                    self.line(&" ".repeat(column), &[Text::plain(line)]);
                }
            } else {
                self.line(&start, &[label]);
                self.nested(value, indent + 2, indent + 2, indent + 4);
            }
        }
    }

    /// A list: a table at `table_indent` when every row is a flat record
    /// and the rows fit the terminal, else one item after another, each
    /// behind a dash, with its text at `item_indent`.
    fn collection(&mut self, items: &[Value], table_indent: usize, item_indent: usize) {
        if items.is_empty() {
            self.line(&" ".repeat(table_indent), &[Text::absent("none")]);
            return;
        }
        if self.table(items, table_indent) {
            return;
        }
        let spaced = items
            .iter()
            .any(|item| matches!(item, Value::Object(map) if map.len() > 1));
        for (index, item) in items.iter().enumerate() {
            if spaced && index > 0 {
                self.lines.push(String::new());
            }
            match item {
                Value::Object(map) if !map.is_empty() => {
                    self.fields(&ordered(map), item_indent, true);
                }
                other => {
                    let start = self.start(item_indent, true);
                    if let Some(text) = inline(None, other) {
                        self.line(&start, &[text]);
                    } else {
                        self.lines.push(start.trim_end().to_owned());
                        self.nested(other, item_indent + 2, item_indent + 2, item_indent + 4);
                    }
                }
            }
        }
    }

    /// Writes `items` as a table and returns true, or writes nothing and
    /// returns false when they are not flat records or too wide.
    fn table(&mut self, items: &[Value], indent: usize) -> bool {
        let Some(rows) = items
            .iter()
            .map(Value::as_object)
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        let mut columns: Vec<&str> = Vec::new();
        for row in &rows {
            for key in row.keys() {
                if shown(key) && !columns.contains(&key.as_str()) {
                    columns.push(key);
                }
            }
        }
        if columns.is_empty() {
            return false;
        }
        columns.sort_by_key(|key| rank(key));
        self.table_of(&rows, &columns, indent)
    }

    /// Writes `rows` as a table of `columns`, in that order, and returns
    /// true, or writes nothing and returns false when a cell is not flat or
    /// the table is too wide.
    fn table_of(&mut self, rows: &[&Map<String, Value>], columns: &[&str], indent: usize) -> bool {
        let mut cells = Vec::with_capacity(rows.len());
        for row in rows {
            let mut line = Vec::with_capacity(columns.len());
            for column in columns {
                let cell = match row.get(*column) {
                    // A text of several lines takes a block of its own.
                    Some(value) if text_lines(value).is_some() => return false,
                    Some(value) => match inline(Some(column), value) {
                        Some(cell) => cell,
                        None => return false,
                    },
                    None => Text::absent("-"),
                };
                line.push(cell);
            }
            cells.push(line);
        }
        let headings: Vec<Text> = labels(columns)
            .into_iter()
            .map(|name| Text::painted(escape_control(name).to_uppercase(), Paint::Bold))
            .collect();
        let widths: Vec<usize> = headings
            .iter()
            .enumerate()
            .map(|(index, heading)| {
                cells
                    .iter()
                    .map(|line| line[index].width())
                    .max()
                    .unwrap_or(0)
                    .max(heading.width())
            })
            .collect();
        let total = indent
            .saturating_add(widths.iter().sum::<usize>())
            .saturating_add(COLUMN_GAP * (widths.len() - 1));
        if total > self.terminal.width {
            return false;
        }
        for line in std::iter::once(headings).chain(cells) {
            let mut pieces = Vec::with_capacity(line.len() * 2);
            for (cell, width) in line.into_iter().zip(&widths) {
                let padding = width - cell.width() + COLUMN_GAP;
                pieces.push(cell);
                pieces.push(Text::plain(" ".repeat(padding)));
            }
            self.line(&" ".repeat(indent), &pieces);
        }
        true
    }
}

/// A record's fields with what identifies it first, then what names it,
/// its state, the rest, and its timestamps last. JSON objects arrive
/// sorted by name, which scatters them.
fn ordered(map: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut fields: Vec<_> = map.iter().filter(|(key, _)| shown(key)).collect();
    fields.sort_by_key(|(key, _)| rank(key));
    fields
}

/// Gives every size in `value`, a record with a sharing tier and its
/// vCPUs, its CPU as a renter is told it ([`size_cpu_text`]) in a `cpu`
/// field instead of its `vcpu_count`: its vCPUs alone, `4 vCPU`, as `ghost
/// catalog offerings` and `ghost instance list` say them; the ladder's
/// mid-step and the size after it differ in memory, disk and prices. The
/// tier itself is not shown ([`shown`]). A record with a `cpu` field of its
/// own keeps it, and one without a tier its `vcpu_count`.
fn name_size_cpus(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if !map.contains_key("cpu")
                && map
                    .get("cpu_tier")
                    .is_some_and(|tier| CpuTier::deserialize(tier).is_ok())
                && let Some(vcpu_count) = map
                    .get("vcpu_count")
                    .and_then(Value::as_u64)
                    .and_then(|count| u32::try_from(count).ok())
            {
                map.remove("vcpu_count");
                map.insert("cpu".to_owned(), Value::from(size_cpu_text(vcpu_count)));
            }
            map.values_mut().for_each(name_size_cpus);
        }
        Value::Array(items) => items.iter_mut().for_each(name_size_cpus),
        _ => {}
    }
}

/// Writes every bandwidth limit in `value`, a `bandwidth` record of its
/// `limit_mbit` alone, as `ghost` says it: `200 Mbit/s`, or `no limit`
/// for none, as an instance's and a network price's.
fn name_bandwidths(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(bandwidth) = map.get_mut("bandwidth")
                && let Some(limit) = bandwidth
                    .as_object()
                    .filter(|record| record.len() == 1)
                    .and_then(|record| record.get("limit_mbit"))
            {
                *bandwidth = match limit.as_u64() {
                    Some(mbit) => Value::from(format!("{mbit} Mbit/s")),
                    None => Value::from("no limit"),
                };
            }
            map.values_mut().for_each(name_bandwidths);
        }
        Value::Array(items) => items.iter_mut().for_each(name_bandwidths),
        _ => {}
    }
}

/// Whether a field is shown to a reader. How a size shares its host's
/// CPUs is the platform's own business: its CPU text ([`name_size_cpus`]),
/// memory, disk and prices tell one size from another. `--json` has
/// `cpu_tier` for scripts.
fn shown(key: &str) -> bool {
    // A hosted backup's data key, wrapped for the account's recovery key,
    // is for `ghost` to rewrap on a restore, not for reading. A job's steps
    // and events name each step by its key; no command takes a step's ID,
    // which readers took for the job's.
    !matches!(key, "cpu_tier" | "wrapped_data_key" | "step_id")
}

/// The endings of field names that say the unit of their number, which
/// [`number_text`] shows the value in instead. A suffix that ends another
/// comes after it.
const UNIT_SUFFIXES: [&str; 14] = [
    "_byte_seconds",
    "_bytes_per_second",
    "_bits_per_second",
    "_mebibytes",
    "_bytes",
    "_milliseconds",
    "_seconds",
    "_ns",
    "_ms",
    "_permyriad",
    "_basis_points",
    "_millistars",
    "_millis",
    "_microusd",
];

/// What a reader calls field `key`: its name without the unit its value is
/// shown in, so `available_microusd` reads "available  $500.00" and
/// `price_microusd_per_gib_month` reads "price  $0.02 per GiB month".
fn label(key: &str) -> &str {
    let name = key.split_once("_microusd_per_").map_or_else(
        || {
            UNIT_SUFFIXES
                .iter()
                .find_map(|suffix| key.strip_suffix(suffix))
                .unwrap_or(key)
        },
        |(name, _)| name,
    );
    if name.is_empty() { key } else { name }
}

/// The labels of the fields `keys` of one record or table: each [`label`],
/// or the name as it is where that label would be another field's.
fn labels<'k>(keys: &[&'k str]) -> Vec<&'k str> {
    let short: Vec<&'k str> = keys.iter().map(|&key| label(key)).collect();
    keys.iter()
        .zip(&short)
        .map(|(&key, &name)| {
            let taken = short.iter().filter(|&&other| other == name).count() > 1
                || (name != key && keys.contains(&name));
            if taken { key } else { name }
        })
        .collect()
}

fn rank(key: &str) -> u8 {
    if key == "id" || key.ends_with("_id") {
        0
    } else if matches!(
        key,
        "name"
            | "label"
            | "slug"
            | "code"
            | "display_name"
            | "title"
            | "subject"
            | "kind"
            | "version"
            | "hostname"
    ) {
        1
    } else if is_state(key) {
        2
    } else if is_time(key) {
        4
    } else {
        3
    }
}

/// Whether field `key` holds a point in time, such as `created_at`,
/// `observed_until` or a `deadline`.
fn is_time(key: &str) -> bool {
    key.ends_with("_at") || key.ends_with("_until") || key == "deadline"
}

fn is_state(key: &str) -> bool {
    matches!(key, "state" | "status" | "health")
        || key.ends_with("_state")
        || key.ends_with("_status")
}

/// The paint of a state: green for what is as it should be, yellow for
/// what is on its way or wants attention, red for what failed, and dim for
/// what has ended. A state this does not know keeps the terminal's color.
fn state_paint(state: &str) -> Option<Paint> {
    match state {
        "accepted" | "accepting" | "active" | "assigned" | "available" | "cached" | "completed"
        | "confirmed" | "current" | "done" | "enabled" | "healthy" | "in_use" | "ok" | "online"
        | "ready" | "resolved" | "running" | "succeeded" | "verified" => Some(Paint::Good),
        "acknowledged" | "backing_up" | "backup_retention" | "checking" | "degraded"
        | "deleting" | "deleting_backups" | "deleting_instances" | "deletion_queued"
        | "downloading" | "draining" | "enrolling" | "installing" | "leased" | "left_out"
        | "open" | "ordering" | "paused" | "pending" | "pending_payment" | "preparing"
        | "progress" | "provisioning" | "pruning" | "queued" | "reboot" | "releasing" | "reset"
        | "restoring" | "retiring" | "retry_wait" | "scheduled" | "staging" | "stopping"
        | "submitted" | "submitting" | "terminating" | "under_review" | "unverified"
        | "uploading" | "verifying" | "waiting" | "warning" => Some(Paint::Warn),
        "aborted" | "action_required" | "error" | "expired" | "failed" | "lost" | "offline"
        | "rejected" | "revoked" | "unhealthy" | "unreachable" => Some(Paint::Bad),
        "cancelled" | "closed" | "deleted" | "retired" | "skipped" | "stopped" => Some(Paint::Dim),
        _ => None,
    }
}

/// `value` on one line, or `None` for a record or a list of records, which
/// take lines of their own. `key` is the name of the field it came from.
fn inline(key: Option<&str>, value: &Value) -> Option<Text> {
    Some(match value {
        Value::Null => Text::absent("-"),
        Value::Bool(true) => Text::plain("yes"),
        Value::Bool(false) => Text::plain("no"),
        Value::Number(number) => Text::plain(number_text(key, number)),
        Value::String(text) => string_text(key, text),
        Value::Array(items) if items.is_empty() => Text::absent("none"),
        Value::Object(map) if map.is_empty() => Text::absent("none"),
        Value::Array(items) => {
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                if item.is_array() || item.is_object() {
                    return None;
                }
                parts.push(inline(None, item)?.plain);
            }
            Text {
                plain: parts.join(", "),
                // A fleet machine's flags each name something wrong with it.
                paint: (key == Some("flags")).then_some(Paint::Warn),
            }
        }
        Value::Object(_) => return None,
    })
}

fn string_text(key: Option<&str>, text: &str) -> Text {
    // A line break that ends a server's message says nothing to a reader.
    let text = text.trim_end_matches(['\n', '\r']);
    if text.is_empty() {
        return Text::absent("-");
    }
    if let Some(key) = key {
        if is_time(key)
            && let Ok(time) = DateTime::parse_from_rfc3339(text)
        {
            return Text::plain(
                time.with_timezone(&Utc)
                    .format("%Y-%m-%d %H:%M:%S UTC")
                    .to_string(),
            );
        }
        if is_state(key) {
            return Text {
                plain: escape_control(text).into_owned(),
                paint: state_paint(text),
            };
        }
        // The API's name for the platform's backup storage; the command
        // line calls it hosted, as `--destination hosted` does.
        if key == "destination" && text == "gigahost_s3" {
            return Text::plain("hosted");
        }
    }
    Text::plain(escape_control(text))
}

/// The lines of a text of more than one, such as a ticket message, each
/// escaped on its own; line breaks at its end do not count.
fn text_lines(value: &Value) -> Option<Vec<String>> {
    let text = value.as_str()?.trim_end_matches(['\n', '\r']);
    text.contains('\n').then(|| {
        text.split('\n')
            .map(|line| escape_control(line.trim_end_matches('\r')).into_owned())
            .collect()
    })
}

/// A number in the unit its field is named after: bytes, memory held over
/// time, a bit rate, a duration, a share, stars, or an amount of money. Any
/// other number is as it is.
fn number_text(key: Option<&str>, number: &Number) -> String {
    let Some(key) = key else {
        return number.to_string();
    };
    if let Some(value) = number.as_u64() {
        let wide = u128::from(value);
        // Memory held over time, such as 1 GiB for 15 minutes, which the
        // `_seconds` below would take for a duration.
        if key.ends_with("_byte_seconds") {
            return format!("{}-hours", scaled(wide / 3_600, 1024, &BINARY_UNITS));
        }
        if key.ends_with("_bytes") {
            return scaled(wide, 1024, &BINARY_UNITS);
        }
        if key.ends_with("_mebibytes") {
            return scaled(wide * 1_048_576, 1024, &BINARY_UNITS);
        }
        if key.ends_with("_bits_per_second") {
            return scaled(wide, 1000, &BIT_RATE_UNITS);
        }
        // Traffic in bits, as the catalog's network tests measure it.
        if key.ends_with("_bytes_per_second") {
            return scaled(wide * 8, 1000, &BIT_RATE_UNITS);
        }
        if key.ends_with("_seconds") {
            return duration(value);
        }
        if key.ends_with("_milliseconds") {
            return duration(value / 1_000);
        }
        if key.ends_with("_ns") {
            return nanoseconds(value);
        }
        if key.ends_with("_permyriad") || key.ends_with("_basis_points") {
            return format!("{}.{:02}%", value / 100, value % 100);
        }
        if key.ends_with("_ms") {
            return format!("{value} ms");
        }
        // Thousandths of what the CPUs could have run.
        if key.ends_with("_utilization_millis") || key.ends_with("_steal_millis") {
            return format!("{}.{}%", value / 10, value % 10);
        }
        // MMX in atomic units, of which one MMX is 1,000,000.
        if key.ends_with("_mmx_atomic") {
            return mmx_text(value);
        }
        if key.ends_with("_millistars") {
            return format!("{} stars", thousandths(value));
        }
        if key.ends_with("_millis") {
            return thousandths(value);
        }
    }
    number
        .as_i64()
        .and_then(|value| money(key, value))
        .unwrap_or_else(|| number.to_string())
}

/// Atomic MMX units as MMX with trailing zeros trimmed: `5 MMX`,
/// `0.25 MMX`. One MMX is 1,000,000 atomic units.
pub(crate) fn mmx_text(atomic: u64) -> String {
    let fraction = format!("{:06}", atomic % 1_000_000);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        format!("{} MMX", atomic / 1_000_000)
    } else {
        format!("{}.{fraction} MMX", atomic / 1_000_000)
    }
}

/// A decimal string of dollars as shown, such as an MMX rate: shown
/// without trailing zeros but with cents (`0.100000000000000000` is
/// `$0.10`, `0.3125` is `$0.3125`).
pub(crate) fn decimal_dollars(rate: &str) -> String {
    let Some((whole, decimals)) = rate.split_once('.') else {
        return format!("${rate}.00");
    };
    let decimals = decimals.trim_end_matches('0');
    format!("${whole}.{decimals:0<2}")
}

/// `value` in the largest unit it fills, rounded to a tenth of it.
fn scaled(value: u128, base: u128, units: &[&str]) -> String {
    let mut unit = 1;
    let mut index = 0;
    while index + 1 < units.len() && value >= unit * base {
        unit *= base;
        index += 1;
    }
    if index == 0 {
        return format!("{value} {}", units[0]);
    }
    let tenths = (value * 10 + unit / 2) / unit;
    if tenths.is_multiple_of(10) {
        format!("{} {}", tenths / 10, units[index])
    } else {
        format!("{}.{} {}", tenths / 10, tenths % 10, units[index])
    }
}

/// Thousandths as a decimal number, exactly.
fn thousandths(value: u64) -> String {
    let fraction = format!("{:03}", value % 1_000);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        (value / 1_000).to_string()
    } else {
        format!("{}.{fraction}", value / 1_000)
    }
}

/// Nanoseconds as seconds to the hundredth under a minute, such as CPU
/// time, and as a [`duration`] from a minute on.
fn nanoseconds(value: u64) -> String {
    let seconds = value / 1_000_000_000;
    if seconds >= 60 {
        return duration(seconds);
    }
    let hundredths = (value + 5_000_000) / 10_000_000;
    format!("{}.{:02} s", hundredths / 100, hundredths % 100)
}

/// `seconds` in its largest unit and, when it is not whole, the next one.
pub(crate) fn duration(seconds: u64) -> String {
    const UNITS: [(&str, u64); 4] = [("d", 86_400), ("h", 3_600), ("m", 60), ("s", 1)];
    let Some(first) = UNITS.iter().position(|(_, size)| seconds >= *size) else {
        return "0s".to_owned();
    };
    let (name, size) = UNITS[first];
    let mut text = format!("{}{name}", seconds / size);
    if let Some((name, size)) = UNITS.get(first + 1) {
        let rest = seconds % UNITS[first].1 / size;
        if rest > 0 {
            let _ = write!(text, " {rest}{name}");
        }
    }
    text
}

/// Micro-dollars as [`dollars`], with the unit of a price after it; a
/// backup price per GiB as [`exact_dollars`]. A key that is the unit alone,
/// as a host's compute earnings name theirs (`microusd_per_month`), is a
/// price too.
fn money(key: &str, microusd: i64) -> Option<String> {
    let unit = if key == "microusd" || key.ends_with("_microusd") {
        None
    } else {
        Some(
            key.strip_prefix("microusd_per_")
                .or_else(|| key.split_once("_microusd_per_").map(|(_, unit)| unit))?,
        )
    };
    let sign = if microusd < 0 { "-" } else { "" };
    let magnitude = microusd.unsigned_abs();
    let amount = match unit {
        Some("gib" | "gib_month") => format!("{sign}{}", exact_dollars(magnitude)),
        _ => format!("{sign}{}", dollars(magnitude)),
    };
    Some(match unit {
        Some(unit) => format!("{amount} per {}", unit_words(unit)),
        None => amount,
    })
}

/// Below this many micro-dollars, two cents, an amount is shown to the
/// hundredth of a cent; from it on, to the cent.
const SMALL_AMOUNT_MICROUSD: u64 = 20_000;

/// Micro-dollars as dollars rounded to the cent, `$1.26`, or, under two
/// cents, to the hundredth of a cent without the zeros that end it,
/// `$0.0016` and `$0.007`, but always with cents: `$0.01`. Nothing is
/// `$0.00`.
pub(crate) fn dollars(microusd: u64) -> String {
    if microusd >= SMALL_AMOUNT_MICROUSD {
        let cents = rounded(microusd, 10_000);
        return format!("${}.{:02}", cents / 100, cents % 100);
    }
    let hundredths = rounded(microusd, 100);
    let mut fraction = format!("{:04}", hundredths % 10_000);
    while fraction.len() > 2 && fraction.ends_with('0') {
        fraction.pop();
    }
    format!("${}.{fraction}", hundredths / 10_000)
}

/// Micro-dollars as dollars with every decimal they have and at least two,
/// nothing rounded: `$0.001`, `$0.0125`, `$0.03`. Backup prices, which are
/// per GiB, show so everywhere (the website too), since renters compare
/// them per GiB, which is how they are set and charged.
pub(crate) fn exact_dollars(microusd: u64) -> String {
    let fraction = format!("{:06}", microusd % 1_000_000);
    let kept = fraction.trim_end_matches('0').len().max(2);
    format!("${}.{}", microusd / 1_000_000, &fraction[..kept])
}

/// `value` in units of `unit`, rounded half up.
const fn rounded(value: u64, unit: u64) -> u64 {
    value / unit + (value % unit >= unit / 2) as u64
}

/// Bits per second in the largest decimal unit they fill: `45.9 Mbit/s`.
pub(crate) fn bit_rate(bits_per_second: u64) -> String {
    scaled(u128::from(bits_per_second), 1000, &BIT_RATE_UNITS)
}

/// A byte count in the largest binary unit it fills: `5.5 GiB`.
pub(crate) fn binary_size(bytes: u64) -> String {
    scaled(u128::from(bytes), 1024, &BINARY_UNITS)
}

/// The unit of a price as it is written: `gib_month` is "GiB month".
fn unit_words(unit: &str) -> String {
    unit.split('_')
        .map(|word| match word {
            "kib" => "KiB",
            "mib" => "MiB",
            "gib" => "GiB",
            "tib" => "TiB",
            "vcpu" => "vCPU",
            "mmx" => "MMX",
            other => other,
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod bit_rate_tests {
    use super::*;

    /// The unit a rate is written in at each boundary, chosen before rounding.
    #[test]
    fn a_bit_rate_takes_the_largest_unit_it_fills() {
        for (bits, shown) in [
            (999, "999 bit/s"),
            (1_000, "1 kbit/s"),
            (512_000, "512 kbit/s"),
            (999_949, "999.9 kbit/s"),
            (999_950, "1000 kbit/s"),
            (1_000_000, "1 Mbit/s"),
            (45_900_000, "45.9 Mbit/s"),
            (999_949_999, "999.9 Mbit/s"),
            (999_950_000, "1000 Mbit/s"),
            (1_000_000_000, "1 Gbit/s"),
            (2_000_000_000, "2 Gbit/s"),
            (1_000_000_000_000, "1 Tbit/s"),
            (1_500_000_000_000_000, "1500 Tbit/s"),
        ] {
            assert_eq!(bit_rate(bits), shown, "{bits}");
        }
    }
}

#[cfg(test)]
mod exact_dollars_tests {
    use super::*;

    /// A backup price per GiB shows every decimal it has, at least two;
    /// other amounts keep the cent, or the hundredth of a cent when small.
    #[test]
    fn a_backup_price_per_gib_shows_every_decimal() {
        assert_eq!(exact_dollars(0), "$0.00");
        assert_eq!(exact_dollars(1_000), "$0.001");
        assert_eq!(exact_dollars(1_250), "$0.00125");
        assert_eq!(exact_dollars(12_500), "$0.0125");
        assert_eq!(exact_dollars(30_000), "$0.03");
        assert_eq!(exact_dollars(21_500), "$0.0215");
        assert_eq!(exact_dollars(1_000_000), "$1.00");
        assert_eq!(exact_dollars(5_514_352), "$5.514352");
        assert_eq!(
            money("creation_charge_microusd_per_gib", 1_250).as_deref(),
            Some("$0.00125 per GiB")
        );
        assert_eq!(
            money("storage_charge_microusd_per_gib_month", 21_500).as_deref(),
            Some("$0.0215 per GiB month")
        );
        assert_eq!(
            money("traffic_microusd_per_tib", 21_500).as_deref(),
            Some("$0.02 per TiB")
        );
        assert_eq!(
            money("microusd_per_month", 2_295_000).as_deref(),
            Some("$2.30 per month")
        );
        assert_eq!(dollars(1_250), "$0.0013");
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Atomic MMX units (1,000,000 to an MMX) show as MMX.
    #[test]
    fn mmx_atomic_amounts_show_as_mmx() {
        assert_eq!(mmx_text(0), "0 MMX");
        assert_eq!(mmx_text(5_000_000), "5 MMX");
        assert_eq!(mmx_text(250_000), "0.25 MMX");
        assert_eq!(mmx_text(1_234_567), "1.234567 MMX");
        let text = render(
            &json!({"amount_mmx_atomic": 42_000_000, "minimum_deposit_mmx_atomic": 1_500_000}),
            PLAIN,
        );
        assert!(
            text.contains("42 MMX") && text.contains("1.5 MMX"),
            "{text}"
        );
        assert_eq!(decimal_dollars("0.100000000000000000"), "$0.10");
        assert_eq!(decimal_dollars("0.3125"), "$0.3125");
        assert_eq!(decimal_dollars("2"), "$2.00");
    }

    const PLAIN: Terminal = Terminal::plain();
    const COLORS: Terminal = Terminal {
        colors: true,
        width: 80,
    };

    #[test]
    fn a_record_lists_its_fields_in_one_column_and_its_parts_under_headings() {
        let instance = json!({
            "created_at": "2026-09-26T12:29:02.123456Z",
            "instance_id": "0199a1b2",
            "label": "web",
            "memory_bytes": 8_589_934_592_u64,
            "state": "running",
            "deleted_at": null,
            "addresses": ["203.0.113.7", "2001:db8::1"],
            "offering": {"cpu_cores": 4, "price_microusd_per_gib_month": 20_000},
            "events": [],
        });
        assert_eq!(
            render(&instance, PLAIN),
            "  instance_id  0199a1b2
  label        web
  state        running
  addresses    203.0.113.7, 2001:db8::1
  events       none
  memory       8 GiB
  created_at   2026-09-26 12:29:02 UTC
  deleted_at   -

  ==> offering
      cpu_cores   4
      price       $0.02 per GiB month"
        );
    }

    /// `ghost catalog images` shows each image's minimum memory beside its
    /// minimum disk, as a size; an older backend's answer without it reads
    /// as none.
    #[test]
    fn the_images_show_their_minimum_memory_as_a_size() {
        let images: Vec<gigahost_client_api::website::ImageView> = serde_json::from_value(json!([
            {"image_id": "01a00000-0000-7000-8000-000000000026", "slug": "ubuntu-26.04",
             "display_name": "Ubuntu 26.04 LTS", "architecture": "x86_64",
             "minimum_disk_bytes": 8_589_934_592_u64, "minimum_memory_bytes": 1_073_741_824_u64},
            {"image_id": "01a00000-0000-7000-8000-000000000024", "slug": "ubuntu-24.04",
             "display_name": "Ubuntu 24.04 LTS", "architecture": "x86_64",
             "minimum_disk_bytes": 4_294_967_296_u64},
        ]))
        .unwrap();
        assert_eq!(images[1].minimum_memory_bytes, 0);
        assert_eq!(
            render(&serde_json::to_value(&images).unwrap(), PLAIN),
            "  IMAGE_ID                              DISPLAY_NAME      SLUG          \
             ARCHITECTURE  MINIMUM_DISK  MINIMUM_MEMORY
  01a00000-0000-7000-8000-000000000026  Ubuntu 26.04 LTS  ubuntu-26.04  \
             x86_64        8 GiB         1 GiB
  01a00000-0000-7000-8000-000000000024  Ubuntu 24.04 LTS  ubuntu-24.04  \
             x86_64        4 GiB         0 B"
        );
    }

    /// A label leaves out the unit its value is shown in, unless another
    /// field of the record or table already goes by the shorter name.
    #[test]
    fn labels_name_what_is_shown_not_the_unit_it_was_sent_in() {
        let balance = json!({
            "available_microusd": 500_000_000, "reserved_microusd": 25_000_000,
            "progress_permyriad": 2_200, "uptime_basis_points": 9_988,
            "memory_byte_seconds": 978_435_319_304_u64, "microusd": 1,
        });
        assert_eq!(
            render(&balance, PLAIN),
            "  available   $500.00
  memory      259.2 MiB-hours
  microusd    $0.00
  progress    22.00%
  reserved    $25.00
  uptime      99.88%"
        );
        let clashing = json!([{"size": "small", "size_bytes": 1024, "disk_bytes": 2048}]);
        assert_eq!(
            render(&clashing, PLAIN),
            "  DISK   SIZE   SIZE_BYTES\n  2 KiB  small  1 KiB"
        );
        assert_eq!(
            labels(&["a_ms", "a_seconds", "b_ns"]),
            ["a_ms", "a_seconds", "b"]
        );
    }

    #[test]
    fn a_list_of_flat_records_is_a_table_until_it_is_too_wide() {
        let hosts = json!([
            {"host_id": "a1", "label": "alpha", "health": "healthy", "uptime_seconds": 90_061},
            {"host_id": "b2", "label": "beta", "health": "degraded"},
        ]);
        assert_eq!(
            render(&hosts, PLAIN),
            "  HOST_ID  LABEL  HEALTH    UPTIME
  a1       alpha  healthy   1d 1h
  b2       beta   degraded  -"
        );
        let narrow = Terminal {
            colors: false,
            width: 33,
        };
        assert_eq!(
            render(&hosts, narrow),
            "    - host_id     a1
      label       alpha
      health      healthy
      uptime      1d 1h

    - host_id     b2
      label       beta
      health      degraded"
        );
    }

    /// A list command's rows keep the columns in the order given, as a
    /// table or, when it is too wide, as blocks, and the next page's cursor
    /// comes after them.
    #[test]
    fn rows_keep_their_columns_in_order() {
        let rows = [
            json!({"posted_at": "2026-09-30T13:50:00.5Z", "kind": "usage",
                   "amount_microusd": -1_647, "instance_id": "i1"}),
            json!({"posted_at": "2026-09-30T13:40:58Z", "kind": "instance_creation",
                   "amount_microusd": -800_000, "instance_id": null}),
        ];
        let columns = ["posted_at", "kind", "amount_microusd", "instance_id"];
        assert_eq!(
            render_rows(&columns, &rows, Some("c2"), PLAIN),
            "  POSTED_AT                KIND               AMOUNT    INSTANCE_ID
  2026-09-30 13:50:00 UTC  usage              -$0.0016  i1
  2026-09-30 13:40:58 UTC  instance_creation  -$0.80    -

  next_cursor  c2"
        );
        let narrow = Terminal {
            colors: false,
            width: 40,
        };
        assert_eq!(
            render_rows(&columns[..3], &rows[..1], None, narrow),
            "    - posted_at   2026-09-30 13:50:00 UTC
      kind        usage
      amount      -$0.0016"
        );
        assert_eq!(render_rows(&columns, &[], None, PLAIN), "  none");
    }

    /// A job's steps are told apart by their keys, which its events name
    /// too; their IDs, which no command takes, are left out.
    #[test]
    fn steps_are_named_by_their_keys() {
        let job = json!({"job_id": "j1", "steps": [{"step_id": "s1", "step_key": "upload_parts"}],
            "events": [{"event_id": 7, "step_id": "s1", "step_key": "upload_parts"}]});
        let text = render(&job, PLAIN);
        assert!(!text.contains("s1") && !text.contains("STEP_ID"), "{text}");
        assert!(text.contains("upload_parts"), "{text}");
    }

    /// A backup's wrapped data key is not for reading, and its destination
    /// reads as the command line names it.
    #[test]
    fn a_backup_reads_as_the_command_line_names_it() {
        let backup = json!({"backup_id": "b1", "destination": "gigahost_s3",
            "wrapped_data_key": "AAAA", "status": "available"});
        assert_eq!(
            render(&backup, PLAIN),
            "  backup_id    b1
  status       available
  destination  hosted"
        );
    }

    #[test]
    fn lists_nest_below_their_label() {
        let rollout = json!({
            "version": "20260926T122902Z-0059f7c9db1f",
            "targets": [
                {"machine_id": "r1", "state": "done", "checks": [{"name": "status", "passed": true}]},
                {"machine_id": "g1", "state": "pending", "checks": []},
            ],
            "notes": ["first", "second"],
            "limits": {},
        });
        assert_eq!(
            render(&rollout, PLAIN),
            "  version     20260926T122902Z-0059f7c9db1f
  limits      none
  notes       first, second

  ==> targets
    - machine_id  r1
      state       done
      checks
        NAME    PASSED
        status  yes

    - machine_id  g1
      state       pending
      checks      none"
        );
        assert_eq!(render(&json!([]), PLAIN), "  none");
        assert_eq!(render(&json!({}), PLAIN), "  none");
        assert_eq!(render(&json!("done"), PLAIN), "  done");
        assert_eq!(render(&json!(["a", "b"]), PLAIN), "    - a\n    - b");
    }

    #[test]
    fn colors_follow_the_install_scripts() {
        let job = json!({"job_id": "j1", "state": "failed", "steps": [{"state": "succeeded"}]});
        assert_eq!(
            render(&job, COLORS),
            "  \x1b[1mjob_id\x1b[0m      j1
  \x1b[1mstate\x1b[0m       \x1b[1;31mfailed\x1b[0m

  \x1b[1;95m==>\x1b[0m \x1b[1msteps\x1b[0m
      \x1b[1mSTATE\x1b[0m
      \x1b[32msucceeded\x1b[0m"
        );
        let plain = render(&job, PLAIN);
        assert!(!plain.contains('\x1b'), "{plain:?}");
        assert_eq!(
            render(
                &json!({"flags": ["stale", "disk_full"], "gone": null}),
                COLORS
            ),
            "  \x1b[1mflags\x1b[0m       \x1b[33mstale, disk_full\x1b[0m
  \x1b[1mgone\x1b[0m        \x1b[2m-\x1b[0m"
        );
        assert_eq!(
            paint_state("running", "[running]", true),
            "\x1b[32m[running]\x1b[0m"
        );
        assert_eq!(paint_state("running", "[running]", false), "[running]");
        assert_eq!(paint_state("novel", "[novel]", true), "[novel]");
        assert_eq!(paint_failure("Error:", true), "\x1b[1;31mError:\x1b[0m");
    }

    #[test]
    fn server_text_cannot_reach_the_terminal_as_control_sequences() {
        let hostile = json!({
            "label\u{1b}[2J": "a\u{1b}[31mb\u{7f}c\u{9b}d",
            "state": "running\u{1b}]0;owned\u{7}",
            "items": [{"note": "line\r\nbr\u{1b}[2Jeak"}],
            "tags": ["x\u{85}y\nz"],
        });
        for terminal in [PLAIN, COLORS] {
            let text = render(&hostile, terminal);
            let painted = text.replace("\x1b[1;95m", "").replace("\x1b[1m", "");
            let painted = painted.replace("\x1b[0m", "").replace("\x1b[2m", "");
            assert!(
                !painted.chars().any(|c| c.is_control() && c != '\n'),
                "{text:?}"
            );
            // Each line of a text of several is escaped on its own.
            assert!(
                painted.lines().any(|line| line.trim() == r"br\u{1b}[2Jeak"),
                "{text:?}"
            );
            assert!(text.contains(r"x\u{85}y\nz"), "{text:?}");
        }
    }

    /// A text of several lines, such as a ticket message, continues below
    /// its first line in the value column, and takes the list it is in out
    /// of a table. Line breaks at the end of a text are dropped.
    #[test]
    fn a_text_of_several_lines_is_shown_on_several_lines() {
        let ticket = json!({
            "messages": [
                {"message_number": 1, "author_role": "user",
                 "body": "The address is unreachable.\n\nSince 09:00.\n"},
                {"message_number": 2, "author_role": "support", "body": "Fixed.\n"},
            ],
            "subject": "Unreachable\n",
        });
        assert_eq!(
            render(&ticket, PLAIN),
            "  subject     Unreachable

  ==> messages
    - author_role     user
      body            The address is unreachable.

                      Since 09:00.
      message_number  1

    - author_role     support
      body            Fixed.
      message_number  2"
        );
    }

    /// A field that holds a point in time reads as the others do, whatever
    /// its name ends in.
    #[test]
    fn times_lose_their_fraction_whatever_their_name() {
        let traffic = json!({
            "observed_until": "2026-09-30T09:07:56.107352Z",
            "deadline": "2026-10-07T00:00:00+02:00",
            "note_until": "not a time",
        });
        assert_eq!(
            render(&traffic, PLAIN),
            "  deadline        2026-10-06 22:00:00 UTC
  note_until      not a time
  observed_until  2026-09-30 09:07:56 UTC"
        );
    }

    /// A size is told by its vCPUs alone, memory, disk and prices: how it
    /// shares its host's CPUs is not shown, in a record or in a table.
    #[test]
    fn the_sharing_tier_is_not_shown() {
        let offering = json!({
            "offering_id": "of1_example", "cpu_tier": "shared_2x", "vcpu_count": 2,
            "memory_bytes": 1_u64 << 30,
        });
        let record = render(&offering, Terminal::plain());
        assert!(record.contains("\n  cpu          2 vCPU\n"), "{record}");
        assert!(
            !record.contains("tier")
                && !record.contains("shared")
                && !record.contains("core")
                && !record.contains("vcpu_count"),
            "{record}"
        );
        let table = render(&json!([offering.clone(), offering]), Terminal::plain());
        assert!(
            !table.contains("tier") && !table.contains("shared"),
            "{table}"
        );
    }

    /// The ladder's mid-step and the size after it have as many vCPUs and
    /// say them alone, told apart by their memory, in an instance's
    /// upgrades as in a record, also nested; without a tier a record keeps
    /// its `vcpu_count`, and one with a `cpu` of its own keeps that.
    #[test]
    fn a_bandwidth_limit_says_its_rate_or_none() {
        let instance = json!({
            "hostname": "web",
            "bandwidth": {"limit_mbit": 200},
            "network_prices": [{"gateway_tier": null, "bandwidth": {"limit_mbit": null}}],
        });
        let shown = render(&instance, PLAIN);
        assert!(
            shown
                .lines()
                .any(|line| line.split_whitespace().eq(["bandwidth", "200", "Mbit/s"])),
            "{shown}"
        );
        assert!(shown.contains("no limit"), "{shown}");
        assert!(!shown.contains("limit_mbit"), "{shown}");
    }

    #[test]
    fn a_size_says_its_vcpus_alone() {
        let upgrade = |tier: &str, memory_gib: u64| {
            json!({
                "offering_id": format!("of2_{tier}"), "cpu_tier": tier, "vcpu_count": 4,
                "memory_bytes": memory_gib << 30, "available": true,
            })
        };
        let upgrades = render(
            &json!([upgrade("shared_2x", 8), upgrade("shared_1x", 16)]),
            Terminal::plain(),
        );
        assert_eq!(
            upgrades,
            "  OFFERING_ID    AVAILABLE  CPU     MEMORY
  of2_shared_2x  yes        4 vCPU  8 GiB
  of2_shared_1x  yes        4 vCPU  16 GiB"
        );
        let nested = render(
            &json!({"instance_id": "i", "size": upgrade("shared_4x", 1)}),
            Terminal::plain(),
        );
        assert!(nested.contains("cpu          4 vCPU\n"), "{nested}");
        let older = render(
            &json!({"instance_id": "i", "cpu_tier": null, "vcpu_count": 4}),
            Terminal::plain(),
        );
        assert!(older.contains("vcpu_count   4"), "{older}");
        let own = render(
            &json!({"cpu": "EPYC", "cpu_tier": "shared_2x", "vcpu_count": 4}),
            Terminal::plain(),
        );
        assert!(own == "  cpu         EPYC\n  vcpu_count  4", "{own}");
    }

    #[test]
    fn numbers_take_the_unit_in_their_name() {
        let number = |key: &str, value: Value| inline(Some(key), &value).unwrap().plain;
        assert_eq!(number("root_disk_total_bytes", json!(512)), "512 B");
        assert_eq!(number("memory_bytes", json!(1_610_612_736_u64)), "1.5 GiB");
        assert_eq!(number("memory_bytes", json!(u64::MAX)), "16 EiB");
        assert_eq!(number("maximum_billable_mebibytes", json!(2048)), "2 GiB");
        assert_eq!(
            number("bandwidth_limit_bits_per_second", json!(2_500_000_000_u64)),
            "2.5 Gbit/s"
        );
        assert_eq!(number("uptime_seconds", json!(0)), "0s");
        assert_eq!(
            number("host_enrollment_token_lifetime_seconds", json!(10_800)),
            "3h"
        );
        assert_eq!(number("pause_seconds", json!(5_430)), "1h 30m");
        assert_eq!(number("uptime_seconds", json!(86_430)), "1d");
        assert_eq!(number("progress_permyriad", json!(1_234)), "12.34%");
        assert_eq!(number("lowest_latency_ms", json!(18)), "18 ms");
        assert_eq!(number("load_average_millis", json!(1_250)), "1.25");
        assert_eq!(number("load_average_millis", json!(2_000)), "2");
        // Usage and reliability, as `instance usage` and `catalog
        // provider` print them.
        assert_eq!(
            number("memory_byte_seconds", json!(978_435_319_304_u64)),
            "259.2 MiB-hours"
        );
        assert_eq!(
            number("memory_byte_seconds", json!(4_638_564_679_680_u64)),
            "1.2 GiB-hours"
        );
        assert_eq!(number("cpu_utilization_millis", json!(47)), "4.7%");
        assert_eq!(number("cpu_utilization_millis", json!(1_000)), "100.0%");
        assert_eq!(number("cpu_steal_millis", json!(1)), "0.1%");
        assert_eq!(
            number("network_ingress_bytes_per_second", json!(17_116)),
            "136.9 kbit/s"
        );
        assert_eq!(number("cpu_time_ns", json!(12_345_678_901_u64)), "12.35 s");
        assert_eq!(number("cpu_time_ns", json!(0)), "0.00 s");
        assert_eq!(number("cpu_time_ns", json!(3_725_000_000_000_u64)), "1h 2m");
        assert_eq!(number("sampled_milliseconds", json!(900_000)), "15m");
        // The vCPU time a usage row's CPU time is a share of.
        assert_eq!(number("vcpu_milliseconds", json!(7_200_000)), "2h");
        assert_eq!(
            number("observed_milliseconds", json!(1_962_244_595)),
            "22d 17h"
        );
        assert_eq!(number("uptime_basis_points", json!(9_988)), "99.88%");
        assert_eq!(
            number("provider_rating_millistars", json!(3_092)),
            "3.092 stars"
        );
        assert_eq!(
            number("host_creation_charge_microusd", json!(1_000_000)),
            "$1.00"
        );
        assert_eq!(number("balance_microusd", json!(-1_234_560)), "-$1.23");
        assert_eq!(number("balance_microusd", json!(1_235_000)), "$1.24");
        assert_eq!(number("balance_microusd", json!(0)), "$0.00");
        // Under two cents an amount keeps up to four decimals, rounded too.
        assert_eq!(number("usage_microusd", json!(-1_647)), "-$0.0016");
        assert_eq!(number("usage_microusd", json!(19_999)), "$0.02");
        assert_eq!(number("usage_microusd", json!(7_002)), "$0.007");
        assert_eq!(number("usage_microusd", json!(10_000)), "$0.01");
        assert_eq!(number("usage_microusd", json!(12_881)), "$0.0129");
        assert_eq!(number("usage_microusd", json!(20_000)), "$0.02");
        assert_eq!(number("usage_microusd", json!(1)), "$0.00");
        assert_eq!(
            number("network_microusd_per_tib", json!(10_240_000)),
            "$10.24 per TiB"
        );
        assert_eq!(number("cpu_cores", json!(4)), "4");
        assert_eq!(number("load_average", json!(0.25)), "0.25");
        assert_eq!(number("memory_bytes", json!(-1)), "-1");
        assert_eq!(inline(None, &json!(2048)).unwrap().plain, "2048");
        assert_eq!(number("created_at", json!("not a time")), "not a time");
    }
}
