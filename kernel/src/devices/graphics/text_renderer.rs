use super::framebuffer::{Color, FrameBuffer, Point};
use alloc::{collections::BTreeMap, vec::Vec};
use lazy_static::lazy_static;
use spin::Mutex;

use fontdue::{Font, FontSettings};

/// Represents text alignment options
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextAlign {
    Left,
    Center,
    Right,
}

/// Represents a glyph cache entry
#[derive(Debug)]
struct CachedGlyph {
    /// Width of the glyph in pixels
    pub width: usize,
    /// Height of the glyph in pixels
    pub height: usize,
    /// Horizontal offset for rendering
    pub xmin: i32,
    /// Vertical offset for rendering
    pub ymin: i32,
    /// Horizontal advance (spacing) for the glyph
    pub advance: usize,
    /// Bitmap data (coverage values 0-255)
    pub bitmap: Vec<u8>,
}

pub static FONT_DATA: &[u8] = include_bytes!("../../../../resources/fonts/Comfortaa-Regular.ttf");

/// Text renderer using Fontdue for TTF support
pub struct TextRenderer {
    /// The loaded font
    font: Font,
    /// Cache of rasterized glyphs to improve performance
    cache: BTreeMap<(char, u32), CachedGlyph>,
}

impl TextRenderer {
    /// Create a new text renderer with the given font data
    pub fn new(font_data: &[u8]) -> Result<Self, &'static str> {
        let settings = FontSettings {
            scale: 40.0,
            ..FontSettings::default()
        };

        let font =
            Font::from_bytes(font_data, settings).map_err(|_| "Failed to parse font data")?;

        Ok(Self {
            font,
            cache: BTreeMap::new(),
        })
    }

    /// Calculate the width of text when rendered
    pub fn calculate_text_width(&mut self, text: &str, size: f32) -> usize {
        let mut width = 0;

        for c in text.chars() {
            let size_key = (size * 10.0) as u32; // Round to nearest tenth for cache

            // Get or create cached glyph metrics
            let glyph = self.cache.entry((c, size_key)).or_insert_with(|| {
                let (metrics, bitmap) = self.font.rasterize(c, size);
                CachedGlyph {
                    width: metrics.width,
                    height: metrics.height,
                    xmin: metrics.xmin,
                    ymin: metrics.ymin,
                    advance: metrics.advance_width as usize,
                    bitmap,
                }
            });

            width += glyph.advance;
        }

        width
    }

    /// Render text at the specified position
    pub fn render_text(
        &mut self,
        fb: &mut FrameBuffer,
        text: &str,
        position: Point,
        size: f32,
        color: Color,
        align: TextAlign,
    ) {
        let text_width = self.calculate_text_width(text, size);
        let mut cursor_x = match align {
            TextAlign::Left => position.x,
            TextAlign::Center => position.x.saturating_sub(text_width / 2),
            TextAlign::Right => position.x.saturating_sub(text_width),
        };
        let cursor_y = position.y;

        for c in text.chars() {
            let size_key = (size * 10.0) as u32; // Round to nearest tenth for cache

            let glyph = self.cache.entry((c, size_key)).or_insert_with(|| {
                let (metrics, bitmap) = self.font.rasterize(c, size);
                CachedGlyph {
                    width: metrics.width,
                    height: metrics.height,
                    xmin: metrics.xmin,
                    ymin: metrics.ymin,
                    advance: metrics.advance_width as usize,
                    bitmap,
                }
            });

            for y in 0..glyph.height {
                for x in 0..glyph.width {
                    let alpha = glyph.bitmap[y * glyph.width + x];
                    if alpha > 0 {
                        let alpha_f = alpha as f32 / 255.0;
                        let mut pixel_color = color;
                        pixel_color.a = (alpha_f * color.a as f32) as u8;

                        let px = cursor_x as i32 + x as i32 + glyph.xmin;
                        let py = cursor_y as i32 + y as i32 + glyph.ymin;

                        if px < 0 || py < 0 {
                            continue;
                        }

                        let px = px as usize;
                        let py = py as usize;

                        if px < fb.width() && py < fb.height() {
                            fb.set_pixel(px, py, pixel_color);
                        }
                    }
                }
            }

            cursor_x += glyph.advance;
        }
    }
}

lazy_static! {
    /// Global text renderer
    pub static ref TEXT_RENDERER: Mutex<TextRenderer> = {
        let renderer = TextRenderer::new(FONT_DATA).expect("Failed to initialize text renderer");

        Mutex::new(renderer)
    };
}

/// Draw text to the provided framebuffer
pub fn draw_text(fb: &mut FrameBuffer, text: &str, x: usize, y: usize, size: f32, color: Color) {
    draw_text_aligned(fb, text, x, y, size, color, TextAlign::Left);
}

/// Draw aligned text to the provided framebuffer
pub fn draw_text_aligned(
    fb: &mut FrameBuffer,
    text: &str,
    x: usize,
    y: usize,
    size: f32,
    color: Color,
    align: TextAlign,
) {
    TEXT_RENDERER
        .lock()
        .render_text(fb, text, Point::new(x, y), size, color, align);
}

/// Calculate the width of text when rendered
pub fn calculate_text_width(text: &str, size: f32) -> usize {
    TEXT_RENDERER.lock().calculate_text_width(text, size)
}
