use crate::events::AppEvent;
use crate::fonts;
use crate::tezos_signer;

use super::Page as PageTrait;
use crossbeam_channel::Sender;
use embedded_graphics::{
    Drawable,
    pixelcolor::BinaryColor,
    prelude::*,
    primitives::{Line, PrimitiveStyle},
};
use russignol_signer_lib::{HighWatermark, bls::PublicKeyHash};
use std::sync::{Arc, RwLock};
use u8g2_fonts::{
    FontRenderer,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
};

/// Capitalize a key alias for display (e.g. "consensus" → "Consensus")
fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

struct KeyInfo {
    alias: String,
    pkh: PublicKeyHash,
}

pub struct Page {
    app_sender: Sender<AppEvent>,
    watermark: Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>>,
    keys: Vec<KeyInfo>,
}

impl Page {
    pub fn new(
        app_sender: Sender<AppEvent>,
        watermark: Arc<RwLock<Option<Arc<RwLock<HighWatermark>>>>>,
    ) -> Self {
        let keys = tezos_signer::get_keys()
            .into_iter()
            .filter_map(|k| {
                PublicKeyHash::from_b58check(&k.value)
                    .ok()
                    .map(|pkh| KeyInfo {
                        alias: capitalize(&k.name),
                        pkh,
                    })
            })
            .collect();

        Self {
            app_sender,
            watermark,
            keys,
        }
    }

    fn read_levels(&self, pkh: &PublicKeyHash) -> (Option<u32>, Option<u32>) {
        let guard = match self.watermark.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let Some(wm_arc) = guard.as_ref() else {
            return (None, None);
        };
        let wm = match wm_arc.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let mem_level = wm.get_max_level(pkh);
        let disk_level = wm.get_persisted_level(pkh);
        (mem_level, disk_level)
    }
}

// Layout constants for 250×122 display
use super::DISPLAY_WIDTH;
const MARGIN: i32 = 6;
const HEADER_Y: i32 = 18;
const LINE_Y: i32 = 26;
const HEADER_ROW_Y: i32 = 42;
const DATA_START_Y: i32 = 66;
const DATA_ROW_GAP: i32 = 28;
const COL_KEY_X: i32 = MARGIN;
const COL_MEM_X: i32 = 120;
const COL_DISK_X: i32 = 192;

impl<D: DrawTarget<Color = BinaryColor>> PageTrait<D> for Page {
    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        let font = FontRenderer::new::<fonts::FONT_MEDIUM>();

        // Title
        font.render_aligned(
            "Watermarks",
            Point::new(DISPLAY_WIDTH / 2, HEADER_Y),
            VerticalPosition::Baseline,
            HorizontalAlignment::Center,
            FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();

        // Separator
        Line::new(
            Point::new(MARGIN, LINE_Y),
            Point::new(DISPLAY_WIDTH - MARGIN, LINE_Y),
        )
        .into_styled(PrimitiveStyle::with_stroke(BinaryColor::Off, 1))
        .draw(display)?;

        // Column headers
        font.render_aligned(
            "Key",
            Point::new(COL_KEY_X, HEADER_ROW_Y),
            VerticalPosition::Baseline,
            HorizontalAlignment::Left,
            FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();
        font.render_aligned(
            "Mem",
            Point::new(COL_MEM_X, HEADER_ROW_Y),
            VerticalPosition::Baseline,
            HorizontalAlignment::Center,
            FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();
        font.render_aligned(
            "Disk",
            Point::new(COL_DISK_X, HEADER_ROW_Y),
            VerticalPosition::Baseline,
            HorizontalAlignment::Center,
            FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();

        // Data rows
        for (i, key) in self.keys.iter().enumerate() {
            let y = DATA_START_Y + i32::try_from(i).unwrap_or(0) * DATA_ROW_GAP;
            let (mem_level, disk_level) = self.read_levels(&key.pkh);

            let mem_str = mem_level.map_or_else(|| "—".to_string(), |l| l.to_string());
            let disk_str = disk_level.map_or_else(|| "—".to_string(), |l| l.to_string());

            font.render_aligned(
                key.alias.as_str(),
                Point::new(COL_KEY_X, y),
                VerticalPosition::Baseline,
                HorizontalAlignment::Left,
                FontColor::Transparent(BinaryColor::Off),
                display,
            )
            .ok();
            font.render_aligned(
                mem_str.as_str(),
                Point::new(COL_MEM_X, y),
                VerticalPosition::Baseline,
                HorizontalAlignment::Center,
                FontColor::Transparent(BinaryColor::Off),
                display,
            )
            .ok();
            font.render_aligned(
                disk_str.as_str(),
                Point::new(COL_DISK_X, y),
                VerticalPosition::Baseline,
                HorizontalAlignment::Center,
                FontColor::Transparent(BinaryColor::Off),
                display,
            )
            .ok();
        }

        Ok(())
    }

    fn handle_touch(&mut self, _point: Point) -> bool {
        let _ = self.app_sender.send(AppEvent::ShowMenu);
        false // Whole-page listener
    }
}
