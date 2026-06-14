// Hide the console window in release builds; keep it during development so panics/errors
// are visible. (Must be the very first line of the crate root.)
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Native Windows GUI for the azoth deniable container (KPDC).
//!
//! This file is *only* the egui shell + a worker thread: all crypto orchestration lives in
//! `azoth_gui` (src/core.rs), which calls the `azoth` library. Argon2id at 256 MiB makes a
//! write/read take ~1s+ (re-randomize does several), so every operation runs on a worker
//! thread and the result is delivered back over an mpsc channel; `update()` never blocks.

use azoth::app::{
    create_container, parse_size, read_payload, write_payload, Kdf, ReadOutcome, REC_ITERS,
    REC_MEM_MIB,
};
use eframe::egui;
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::thread;
use zeroize::Zeroizing;

// ---- alchemy / steampunk palette: aged brass & copper, parchment on patinated bronze ----
const BG_DEEP: egui::Color32 = egui::Color32::from_rgb(0x17, 0x11, 0x0c); // near-black, warm
const BG_PANEL: egui::Color32 = egui::Color32::from_rgb(0x20, 0x18, 0x10); // patinated bronze
const BG_INSET: egui::Color32 = egui::Color32::from_rgb(0x2b, 0x20, 0x15);
const W_INACT: egui::Color32 = egui::Color32::from_rgb(0x33, 0x27, 0x19);
const W_HOVER: egui::Color32 = egui::Color32::from_rgb(0x4a, 0x39, 0x23);
const W_ACTIVE: egui::Color32 = egui::Color32::from_rgb(0x5c, 0x48, 0x2c);
const BRASS: egui::Color32 = egui::Color32::from_rgb(0xb0, 0x86, 0x3a);
const BRASS_DIM: egui::Color32 = egui::Color32::from_rgb(0x6e, 0x57, 0x2c);
const COPPER: egui::Color32 = egui::Color32::from_rgb(0xb2, 0x5a, 0x2e);
const GOLD: egui::Color32 = egui::Color32::from_rgb(0xd8, 0xb2, 0x4a);
const PARCH: egui::Color32 = egui::Color32::from_rgb(0xe9, 0xdc, 0xc0);
const PARCH_DIM: egui::Color32 = egui::Color32::from_rgb(0xb7, 0xa8, 0x88);
/// Amber for advisory warnings (bad K, custom KDF, re-randomize data loss) — fits the brass palette.
const WARN: egui::Color32 = egui::Color32::from_rgb(0xE0, 0xA8, 0x2a);

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("azoth — deniable container")
            .with_inner_size([660.0, 600.0])
            .with_min_inner_size([560.0, 520.0]),
        ..Default::default()
    };
    eframe::run_native(
        "azoth",
        native_options,
        Box::new(|cc| {
            install_symbol_font(&cc.egui_ctx);
            apply_alchemy_theme(&cc.egui_ctx);
            Ok(Box::<App>::default())
        }),
    )
}

/// Fold Windows' "Segoe UI Symbol" in as a fallback font so the alchemical/steampunk glyphs
/// (⚗ alembic, ⚙ gear, ⚠) render instead of tofu boxes. Best-effort: if the font isn't found
/// the app still works (those glyphs just won't show).
fn install_symbol_font(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    for path in [
        r"C:\Windows\Fonts\seguisym.ttf",
        r"C:\Windows\Fonts\SegoeUISymbol.ttf",
    ] {
        if let Ok(bytes) = std::fs::read(path) {
            fonts
                .font_data
                .insert("symbols".to_owned(), egui::FontData::from_owned(bytes));
            for fam in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                fonts
                    .families
                    .entry(fam)
                    .or_default()
                    .push("symbols".to_owned());
            }
            break;
        }
    }
    ctx.set_fonts(fonts);
}

/// Dress egui in an aged-alchemy / steampunk skin: brass & copper on patinated bronze,
/// parchment text, lightly rounded "riveted" widgets. Set once at startup.
fn apply_alchemy_theme(ctx: &egui::Context) {
    use egui::style::{Selection, WidgetVisuals};
    use egui::{FontId, Rounding, Stroke, TextStyle};

    let mut style = (*ctx.style()).clone();
    let v = &mut style.visuals;
    v.dark_mode = true;
    v.override_text_color = Some(PARCH);
    v.panel_fill = BG_PANEL;
    v.window_fill = BG_PANEL;
    v.extreme_bg_color = BG_DEEP; // text-edit / log backgrounds
    v.faint_bg_color = BG_INSET;
    v.window_stroke = Stroke::new(1.0, BRASS_DIM);
    v.window_rounding = Rounding::same(4.0);
    v.hyperlink_color = GOLD;
    v.warn_fg_color = WARN;
    v.error_fg_color = COPPER;

    let rounding = Rounding::same(3.0);
    let wv = |bg, stroke, sw: f32, fg| WidgetVisuals {
        bg_fill: bg,
        weak_bg_fill: bg,
        bg_stroke: Stroke::new(sw, stroke),
        fg_stroke: Stroke::new(1.0, fg),
        rounding,
        expansion: 0.0,
    };
    v.widgets.noninteractive = wv(BG_PANEL, BRASS_DIM, 1.0, PARCH_DIM);
    v.widgets.inactive = wv(W_INACT, BRASS_DIM, 1.0, PARCH);
    v.widgets.hovered = wv(W_HOVER, BRASS, 1.2, PARCH);
    v.widgets.active = wv(W_ACTIVE, GOLD, 1.4, PARCH);
    v.widgets.open = wv(W_INACT, BRASS, 1.0, PARCH);
    v.selection = Selection {
        bg_fill: COPPER.linear_multiply(0.5),
        stroke: Stroke::new(1.0, GOLD),
    };

    let s = &mut style.spacing;
    s.item_spacing = egui::vec2(8.0, 8.0);
    s.button_padding = egui::vec2(10.0, 5.0);

    style
        .text_styles
        .insert(TextStyle::Heading, FontId::proportional(26.0));
    style
        .text_styles
        .insert(TextStyle::Body, FontId::proportional(15.0));
    style
        .text_styles
        .insert(TextStyle::Button, FontId::proportional(15.0));
    style
        .text_styles
        .insert(TextStyle::Monospace, FontId::monospace(13.0));

    ctx.set_style(style);
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Create,
    Write,
    Read,
}

/// A finished worker-thread job handed back to the UI thread.
enum Job {
    /// create / write — just a log line (or error).
    Log(Result<String, String>),
    /// read — outcome carries the (zeroizing) plaintext, or an error.
    Read(Result<ReadOutcome, String>),
}

struct App {
    tab: Tab,

    // shared inputs
    container: String,
    k_text: String,
    kdf_mem: String,
    kdf_iters: String,

    // create tab
    size_text: String,

    // write tab
    write_pw: String,
    plaintext: String,
    data_file: String,
    known: String,
    rerandomize: bool,
    all_keys: bool,

    // read tab
    read_pw: String,
    read_output: String,
    read_bytes: Option<Zeroizing<Vec<u8>>>,

    // status log + worker plumbing
    log: String,
    rx: Option<Receiver<Job>>,
    busy: bool,
}

impl Default for App {
    fn default() -> Self {
        App {
            tab: Tab::Create,
            container: String::new(),
            k_text: String::new(),
            kdf_mem: REC_MEM_MIB.to_string(),
            kdf_iters: REC_ITERS.to_string(),
            size_text: "64k".to_string(),
            write_pw: String::new(),
            plaintext: String::new(),
            data_file: String::new(),
            known: String::new(),
            rerandomize: true,
            all_keys: false,
            read_pw: String::new(),
            read_output: String::new(),
            read_bytes: None,
            log: String::new(),
            rx: None,
            busy: false,
        }
    }
}

impl App {
    fn log_line(&mut self, s: &str) {
        if !self.log.is_empty() {
            self.log.push('\n');
        }
        self.log.push_str(s);
    }

    /// Parse the shared K field.
    fn parse_k(&self) -> Result<u64, String> {
        self.k_text
            .trim()
            .parse::<u64>()
            .map_err(|_| "K must be a whole number >= 2".to_string())
    }

    /// Parse the shared KDF cost fields.
    fn parse_kdf(&self) -> Result<Kdf, String> {
        let mem_mib = self
            .kdf_mem
            .trim()
            .parse::<u32>()
            .map_err(|_| "KDF memory (MiB) must be a whole number".to_string())?;
        let iters = self
            .kdf_iters
            .trim()
            .parse::<u32>()
            .map_err(|_| "KDF iterations must be a whole number".to_string())?;
        let kdf = Kdf { mem_mib, iters };
        kdf.validate()?;
        Ok(kdf)
    }

    /// Spawn a worker thread that produces a `Job`, and mark the app busy.
    fn spawn<F>(&mut self, f: F)
    where
        F: FnOnce() -> Job + Send + 'static,
    {
        let (tx, rx) = channel();
        self.rx = Some(rx);
        self.busy = true;
        thread::spawn(move || {
            let _ = tx.send(f());
        });
    }

    fn start_create(&mut self) {
        let path = self.container.trim().to_string();
        if path.is_empty() {
            self.log_line("error: choose a container file path first (Browse…).");
            return;
        }
        let size = match parse_size(&self.size_text) {
            Ok(s) => s,
            Err(e) => return self.log_line(&format!("error: {e}")),
        };
        let k = match self.parse_k() {
            Ok(k) => k,
            Err(e) => return self.log_line(&format!("error: {e}")),
        };
        let kdf = match self.parse_kdf() {
            Ok(k) => k,
            Err(e) => return self.log_line(&format!("error: {e}")),
        };
        self.log_line(&format!("working… creating {path}"));
        self.spawn(move || Job::Log(create_container(&path, size, k, kdf)));
    }

    fn start_write(&mut self) {
        let path = self.container.trim().to_string();
        if path.is_empty() {
            self.log_line("error: choose a container file first (Browse…).");
            return;
        }
        if self.write_pw.is_empty() {
            self.log_line("error: enter a password to write under.");
            return;
        }
        let k = match self.parse_k() {
            Ok(k) => k,
            Err(e) => return self.log_line(&format!("error: {e}")),
        };
        let kdf = match self.parse_kdf() {
            Ok(k) => k,
            Err(e) => return self.log_line(&format!("error: {e}")),
        };
        // Plaintext: the data file if one is given, otherwise the text box (may be empty —
        // the library supports an empty payload).
        let data_file = self.data_file.trim().to_string();
        let plaintext: Vec<u8> = if !data_file.is_empty() {
            match std::fs::read(&data_file) {
                Ok(b) => b,
                Err(e) => {
                    return self.log_line(&format!("error: reading data file {data_file}: {e}"))
                }
            }
        } else {
            self.plaintext.clone().into_bytes()
        };
        let known: Vec<String> = self
            .known
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        let pw = self.write_pw.clone();
        let rerandomize = self.rerandomize;
        let all_keys = self.all_keys;
        self.log_line("working… writing payload");
        self.spawn(move || {
            Job::Log(write_payload(
                &path,
                &pw,
                &plaintext,
                &known,
                k,
                kdf,
                rerandomize,
                all_keys,
            ))
        });
    }

    fn start_read(&mut self) {
        let path = self.container.trim().to_string();
        if path.is_empty() {
            self.log_line("error: choose a container file first (Browse…).");
            return;
        }
        if self.read_pw.is_empty() {
            self.log_line("error: enter a password to read.");
            return;
        }
        let k = match self.parse_k() {
            Ok(k) => k,
            Err(e) => return self.log_line(&format!("error: {e}")),
        };
        let kdf = match self.parse_kdf() {
            Ok(k) => k,
            Err(e) => return self.log_line(&format!("error: {e}")),
        };
        // Clear any previously decrypted bytes (dropping the Zeroizing buffer wipes it).
        self.read_output.clear();
        self.read_bytes = None;
        let pw = self.read_pw.clone();
        self.log_line("working… reading payload");
        self.spawn(move || Job::Read(read_payload(&path, &pw, k, kdf)));
    }

    /// Handle a finished job from the worker thread.
    fn handle_job(&mut self, job: Job) {
        match job {
            Job::Log(Ok(msg)) => self.log_line(&msg),
            Job::Log(Err(e)) => self.log_line(&format!("error: {e}")),
            Job::Read(Ok(ReadOutcome::Found(pt))) => {
                self.read_output = String::from_utf8_lossy(&pt).into_owned();
                self.log_line(&format!(
                    "read OK: decrypted {} byte(s) — shown below; use \"Save to file…\" for exact bytes",
                    pt.len()
                ));
                self.read_bytes = Some(pt);
            }
            Job::Read(Ok(ReadOutcome::NotFound)) => {
                self.log_line("no payload for that password / K / KDF cost — just noise.");
            }
            Job::Read(Err(e)) => self.log_line(&format!("error: {e}")),
        }
    }

    // ---------- UI sections ----------

    fn ui_shared(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("shared")
            .num_columns(2)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                ui.label("Container file:");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.container)
                            .desired_width(360.0)
                            .hint_text("path to the container file"),
                    );
                    if ui.button("Browse…").clicked() {
                        let dialog = rfd::FileDialog::new();
                        let picked = if self.tab == Tab::Create {
                            dialog.save_file()
                        } else {
                            dialog.pick_file()
                        };
                        if let Some(p) = picked {
                            self.container = p.display().to_string();
                        }
                    }
                });
                ui.end_row();

                ui.label("K:");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.k_text)
                            .desired_width(140.0)
                            .hint_text("plane count"),
                    );
                    if ui.button("Suggest prime").clicked() {
                        let n = self.k_text.trim().parse::<u64>().unwrap_or(0);
                        self.k_text = azoth::next_prime_coprime8(n).to_string();
                    }
                });
                ui.end_row();

                ui.label("KDF memory (MiB):");
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.kdf_mem).desired_width(80.0));
                    ui.label("iterations:");
                    ui.add(egui::TextEdit::singleline(&mut self.kdf_iters).desired_width(60.0));
                });
                ui.end_row();
            });

        // Advisory: bad K (mirrors the CLI `warn_if_bad_k`).
        if let Ok(k) = self.parse_k() {
            if !azoth::is_recommended_k(k) {
                ui.colored_label(
                    WARN,
                    "⚠ K is not a prime coprime to 8; plane geometry may be skewed and \
                     deniability weakened. Click \"Suggest prime\" for a good K.",
                );
            }
        }
        // Advisory: custom KDF cost (mirrors the CLI `warn_if_custom_kdf`).
        if self.kdf_mem.trim() != REC_MEM_MIB.to_string()
            || self.kdf_iters.trim() != REC_ITERS.to_string()
        {
            ui.colored_label(
                WARN,
                "⚠ custom KDF cost is part of the credential and isn't stored — you must use \
                 the exact same values to decrypt.",
            );
        }
    }

    fn ui_create(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Size:");
            ui.add(
                egui::TextEdit::singleline(&mut self.size_text)
                    .desired_width(140.0)
                    .hint_text("64k / 512mb / 2gb"),
            );
            ui.label("bytes, or with a unit (binary, 1024-based)");
        });
        ui.add_space(6.0);
        if ui
            .add_enabled(!self.busy, egui::Button::new("Create container"))
            .clicked()
        {
            self.start_create();
        }
    }

    fn ui_write(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("write")
            .num_columns(2)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                ui.label("Password:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.write_pw)
                        .password(true)
                        .desired_width(300.0),
                );
                ui.end_row();

                ui.label("Data file (optional):");
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.data_file).desired_width(300.0));
                    if ui.button("Browse…").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_file() {
                            self.data_file = p.display().to_string();
                        }
                    }
                });
                ui.end_row();
            });

        ui.label("…or plaintext (used only if no data file is chosen):");
        ui.add(
            egui::TextEdit::multiline(&mut self.plaintext)
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        );

        ui.add_space(4.0);
        ui.label("Known passwords — every OTHER password already in the container, one per line:");
        ui.add(
            egui::TextEdit::multiline(&mut self.known)
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        );

        ui.add_space(4.0);
        ui.checkbox(&mut self.rerandomize, "Re-randomize (recommended)");
        ui.add_enabled(
            self.rerandomize,
            egui::Checkbox::new(&mut self.all_keys, "I have supplied ALL passwords"),
        );
        if self.rerandomize {
            ui.colored_label(
                WARN,
                "⚠ Re-randomize rebuilds the WHOLE container from the passwords you supply — \
                 any existing payload whose password you don't list is permanently destroyed.",
            );
        } else {
            ui.colored_label(
                WARN,
                "⚠ In-place write is faster but leaves a multi-snapshot diffing fingerprint \
                 (an adversary who images the file before and after can learn K).",
            );
        }

        ui.add_space(6.0);
        if ui
            .add_enabled(!self.busy, egui::Button::new("Write payload"))
            .clicked()
        {
            self.start_write();
        }
    }

    fn ui_read(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.add(
                egui::TextEdit::singleline(&mut self.read_pw)
                    .password(true)
                    .desired_width(300.0),
            );
        });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.busy, egui::Button::new("Read payload"))
                .clicked()
            {
                self.start_read();
            }
            if self.read_bytes.is_some() && ui.button("Save to file…").clicked() {
                if let Some(p) = rfd::FileDialog::new().save_file() {
                    let res = self
                        .read_bytes
                        .as_ref()
                        .map(|b| std::fs::write(&p, b.as_slice()));
                    match res {
                        Some(Ok(())) => {
                            self.log_line(&format!("saved decrypted bytes to {}", p.display()))
                        }
                        Some(Err(e)) => {
                            self.log_line(&format!("error: saving {}: {e}", p.display()))
                        }
                        None => {}
                    }
                }
            }
        });

        if self.read_bytes.is_some() {
            ui.add_space(6.0);
            ui.label(egui::RichText::new("Decrypted output (UTF-8 lossy view):").color(PARCH_DIM));
            ui.add(
                egui::TextEdit::multiline(&mut self.read_output)
                    .desired_rows(6)
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace)
                    .interactive(false),
            );
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Poll the worker thread.
        if let Some(rx) = &self.rx {
            match rx.try_recv() {
                Ok(job) => {
                    self.rx = None;
                    self.busy = false;
                    self.handle_job(job);
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.rx = None;
                    self.busy = false;
                    self.log_line("error: worker thread ended without a result.");
                }
            }
        }

        // Status log pinned to the bottom.
        egui::TopBottomPanel::bottom("log_panel")
            .resizable(true)
            .min_height(140.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.label(egui::RichText::new("⚙ ledger").color(BRASS).strong());
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut self.log)
                                .desired_width(f32::INFINITY)
                                .desired_rows(8)
                                .font(egui::TextStyle::Monospace)
                                .interactive(false),
                        );
                    });
            });

        let central = egui::Frame::central_panel(&ctx.style())
            .stroke(egui::Stroke::new(1.0, BRASS_DIM))
            .rounding(egui::Rounding::same(4.0))
            .inner_margin(egui::Margin::same(14.0));
        egui::CentralPanel::default()
            .frame(central)
            .show(ctx, |ui| {
                ui.heading(egui::RichText::new("⚗  A Z O T H").color(GOLD));
                ui.label(
                    egui::RichText::new("K-Plane Deniable Container  ·  solve et coagula")
                        .italics()
                        .color(GOLD.linear_multiply(0.85)),
                );
                ui.add_space(2.0);
                ui.label(
                egui::RichText::new(
                    "One block of noise, many secrets. K and the KDF cost are the credential — \
                     never stored, so supply them every time.",
                )
                .color(PARCH_DIM),
            );
                ui.separator();

                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.tab, Tab::Create, "Create");
                    ui.selectable_value(&mut self.tab, Tab::Write, "Write");
                    ui.selectable_value(&mut self.tab, Tab::Read, "Read");
                    if self.busy {
                        ui.separator();
                        ui.spinner();
                        ui.label("working… (Argon2id is deliberately slow)");
                    }
                });
                ui.separator();

                self.ui_shared(ui);
                ui.separator();

                match self.tab {
                    Tab::Create => self.ui_create(ui),
                    Tab::Write => self.ui_write(ui),
                    Tab::Read => self.ui_read(ui),
                }
            });

        // Keep repainting while a job is in flight so the poll above keeps running.
        if self.busy {
            ctx.request_repaint();
        }
    }
}
