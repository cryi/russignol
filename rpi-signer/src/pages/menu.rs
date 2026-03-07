use crate::events::AppEvent;
use crate::fonts;
use crate::widgets::Button;

use super::Page as PageTrait;
use crossbeam_channel::Sender;
use embedded_graphics::{pixelcolor::BinaryColor, prelude::*};
use u8g2_fonts::{
    FontRenderer,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Page {
    app_sender: Sender<AppEvent>,
    buttons: [(Button, AppEvent); 4],
}

// Layout: 2×2 grid on 250×122 display
use super::{DISPLAY_HEIGHT, DISPLAY_WIDTH};
const BUTTON_W: u32 = 110;
const BUTTON_H: u32 = 38;
const GAP_X: i32 = 10;
const GAP_Y: i32 = 8;
const HEADER_H: i32 = 22;

impl Page {
    pub fn new(app_sender: Sender<AppEvent>) -> Self {
        let bw = BUTTON_W.cast_signed();
        let bh = BUTTON_H.cast_signed();
        let grid_w = bw * 2 + GAP_X;
        let grid_h = bh * 2 + GAP_Y;
        let x0 = (DISPLAY_WIDTH - grid_w) / 2;
        let y0 = HEADER_H + (DISPLAY_HEIGHT - HEADER_H - grid_h) / 2;
        let x1 = x0 + bw + GAP_X;
        let y1 = y0 + bh + GAP_Y;

        let size = Size::new(BUTTON_W, BUTTON_H);
        let mut buttons = [
            (Button::new_text(size, "Status"), AppEvent::ShowStatus),
            (Button::new_text(size, "Activity"), AppEvent::ShowSignatures),
            (
                Button::new_text(size, "Watermarks"),
                AppEvent::ShowWatermarks,
            ),
            (
                Button::new_text(size, "Shutdown"),
                AppEvent::RequestShutdown,
            ),
        ];
        buttons[0].0.bounds.top_left = Point::new(x0, y0);
        buttons[1].0.bounds.top_left = Point::new(x1, y0);
        buttons[2].0.bounds.top_left = Point::new(x0, y1);
        buttons[3].0.bounds.top_left = Point::new(x1, y1);

        Self {
            app_sender,
            buttons,
        }
    }
}

impl<D: DrawTarget<Color = BinaryColor>> PageTrait<D> for Page {
    fn draw(&mut self, display: &mut D) -> Result<(), D::Error> {
        let font = FontRenderer::new::<fonts::FONT_MEDIUM>();
        let version_str = format!("Russignol v{VERSION}");
        font.render_aligned(
            version_str.as_str(),
            Point::new(DISPLAY_WIDTH / 2, 15),
            VerticalPosition::Baseline,
            HorizontalAlignment::Center,
            FontColor::Transparent(BinaryColor::Off),
            display,
        )
        .ok();

        for (button, _) in &self.buttons {
            button.draw(display)?;
        }
        Ok(())
    }

    fn handle_touch(&mut self, point: Point) -> bool {
        for (button, event) in &self.buttons {
            if button.contains(point) {
                let _ = self.app_sender.send(event.clone());
                return true;
            }
        }
        false
    }
}
