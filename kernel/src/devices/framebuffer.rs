use alloc::{vec, vec::Vec};
use core::ptr;
use limine::request::FramebufferRequest;
use spin::Mutex;

/// Framebuffer request to the bootloader.
/// Used to get access to video output capabilities.
///
/// TODO: Move to proper frame buffer implementation
#[used]
#[link_section = ".requests"]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

/// Represents an RGBA color with 8 bits per channel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    /// Create a new color with the specified RGBA values
    pub const fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Create a new color from a 32-bit RGBA value
    pub const fn from_rgba(rgba: u32) -> Self {
        Self {
            r: ((rgba >> 24) & 0xFF) as u8,
            g: ((rgba >> 16) & 0xFF) as u8,
            b: ((rgba >> 8) & 0xFF) as u8,
            a: (rgba & 0xFF) as u8,
        }
    }

    /// Convert the color to a 32-bit RGBA value
    pub const fn to_rgba(&self) -> u32 {
        ((self.r as u32) << 24) | ((self.g as u32) << 16) | ((self.b as u32) << 8) | (self.a as u32)
    }
}

/// Some common colors (thanks internet)
pub mod colors {
    use super::Color;

    pub const BLACK: Color = Color::new(0, 0, 0, 255);
    pub const WHITE: Color = Color::new(255, 255, 255, 255);
    pub const RED: Color = Color::new(255, 0, 0, 255);
    pub const GREEN: Color = Color::new(0, 255, 0, 255);
    pub const BLUE: Color = Color::new(0, 0, 255, 255);
    pub const YELLOW: Color = Color::new(255, 255, 0, 255);
    pub const CYAN: Color = Color::new(0, 255, 255, 255);
    pub const MAGENTA: Color = Color::new(255, 0, 255, 255);
    pub const TRANSPARENT: Color = Color::new(0, 0, 0, 0);
}

/// Represents a 2D point on the screen
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    pub x: usize,
    pub y: usize,
}

impl Point {
    /// Create a new point with the specified coordinates
    pub const fn new(x: usize, y: usize) -> Self {
        Self { x, y }
    }
}

/// Represents a rectangle on the screen
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: usize,
    pub y: usize,
    pub width: usize,
    pub height: usize,
}

impl Rect {
    /// Create a new rectangle with the specified position and dimensions
    pub const fn new(x: usize, y: usize, width: usize, height: usize) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    /// Create a new rectangle from two points (top-left and bottom-right)
    pub fn from_points(p1: Point, p2: Point) -> Self {
        let x = core::cmp::min(p1.x, p2.x);
        let y = core::cmp::min(p1.y, p2.y);
        let width = core::cmp::max(p1.x, p2.x) - x;
        let height = core::cmp::max(p1.y, p2.y) - y;
        Self {
            x,
            y,
            width,
            height,
        }
    }

    /// Check if the rectangle contains the specified point
    pub fn contains(&self, point: Point) -> bool {
        point.x >= self.x
            && point.x < self.x + self.width
            && point.y >= self.y
            && point.y < self.y + self.height
    }
}

/// Represents a buffer of pixels
#[derive(Debug)]
pub struct FrameBuffer {
    /// The width of the frame buffer in pixels
    width: usize,
    /// The height of the frame buffer in pixels
    height: usize,
    /// The number of bytes per pixel
    bytes_per_pixel: usize,
    /// The pitch (bytes per scanline) of the frame buffer
    pitch: usize,
    /// The raw pointer to the frame buffer memory
    addr: *mut u8,
    /// The size of the frame buffer in bytes
    size: usize,
    /// Double buffer to reduce screen tearing
    back_buffer: Vec<u8>,
}

unsafe impl Send for FrameBuffer {}
unsafe impl Sync for FrameBuffer {}

impl FrameBuffer {
    /// Create a new frame buffer from the provided Limine framebuffer
    pub fn new(framebuffer: &limine::framebuffer::Framebuffer) -> Option<Self> {
        let width = framebuffer.width() as usize;
        let height = framebuffer.height() as usize;
        let bytes_per_pixel = framebuffer.bpp() as usize / 8;
        let pitch = framebuffer.pitch() as usize;
        let addr = framebuffer.addr();
        let size = pitch * height;

        if width == 0 || height == 0 || bytes_per_pixel == 0 || pitch == 0 || addr.is_null() {
            return None;
        }

        // Create a back buffer for double buffering
        // This is supposed to be good?
        let back_buffer = vec![0; size];

        Some(Self {
            width,
            height,
            bytes_per_pixel,
            pitch,
            addr,
            size,
            back_buffer,
        })
    }

    /// Get the width of the frame buffer in pixels
    pub fn width(&self) -> usize {
        self.width
    }

    /// Get the height of the frame buffer in pixels
    pub fn height(&self) -> usize {
        self.height
    }

    /// Get the dimensions of the frame buffer as a (width, height) tuple
    pub fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    /// Get the number of bytes per pixel
    pub fn bytes_per_pixel(&self) -> usize {
        self.bytes_per_pixel
    }

    /// Get the pitch (bytes per scanline) of the frame buffer
    pub fn pitch(&self) -> usize {
        self.pitch
    }

    /// Get a mutable slice to the back buffer
    pub fn back_buffer_mut(&mut self) -> &mut [u8] {
        &mut self.back_buffer
    }

    /// Calculate the offset in the buffer for a given x and y coordinate
    fn offset(&self, x: usize, y: usize) -> usize {
        y * self.pitch + x * self.bytes_per_pixel
    }

    /// Set a pixel in the back buffer to the specified color
    pub fn set_pixel(&mut self, x: usize, y: usize, color: Color) {
        if x >= self.width || y >= self.height {
            return;
        }

        let offset = self.offset(x, y);
        if offset + self.bytes_per_pixel > self.size {
            return;
        }

        let rgba = color.to_rgba();
        unsafe {
            let ptr = self.back_buffer.as_mut_ptr().add(offset) as *mut u32;
            *ptr = rgba;
        }
    }

    /// Get the color of a pixel in the back buffer
    pub fn get_pixel(&self, x: usize, y: usize) -> Option<Color> {
        if x >= self.width || y >= self.height {
            return None;
        }

        let offset = self.offset(x, y);
        if offset + self.bytes_per_pixel > self.size {
            return None;
        }

        let rgba = unsafe {
            let ptr = self.back_buffer.as_ptr().add(offset) as *const u32;
            *ptr
        };

        Some(Color::from_rgba(rgba))
    }

    /// Fill the entire back buffer with a color
    pub fn clear(&mut self, color: Color) {
        let rgba = color.to_rgba();

        // For faster clearing, fill 4 bytes at a time when possible
        if self.bytes_per_pixel == 4 && self.pitch % 4 == 0 {
            let pixels = self.back_buffer.as_mut_ptr() as *mut u32;
            let count = self.size / 4;

            for i in 0..count {
                unsafe {
                    *pixels.add(i) = rgba;
                }
            }
        } else {
            // Fallback for non-standard pixel formats
            for y in 0..self.height {
                for x in 0..self.width {
                    self.set_pixel(x, y, color);
                }
            }
        }
    }

    /// Draw a horizontal line
    pub fn draw_hline(&mut self, x: usize, y: usize, width: usize, color: Color) {
        let end_x = core::cmp::min(x + width, self.width);
        for curr_x in x..end_x {
            self.set_pixel(curr_x, y, color);
        }
    }

    /// Draw a vertical line
    pub fn draw_vline(&mut self, x: usize, y: usize, height: usize, color: Color) {
        let end_y = core::cmp::min(y + height, self.height);
        for curr_y in y..end_y {
            self.set_pixel(x, curr_y, color);
        }
    }

    /// Draw a line between two points using Bresenham's algorithm
    /// Thanks AoC, although someone should check me on this
    pub fn draw_line(&mut self, x0: usize, y0: usize, x1: usize, y1: usize, color: Color) {
        let (mut x0, mut y0, x1, y1) = (x0 as isize, y0 as isize, x1 as isize, y1 as isize);

        let dx = (x1 - x0).abs();
        let dy = -(y1 - y0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;

        loop {
            if x0 >= 0 && y0 >= 0 && x0 < self.width as isize && y0 < self.height as isize {
                self.set_pixel(x0 as usize, y0 as usize, color);
            }

            if x0 == x1 && y0 == y1 {
                break;
            }

            let e2 = 2 * err;
            if e2 >= dy {
                if x0 == x1 {
                    break;
                }
                err += dy;
                x0 += sx;
            }
            if e2 <= dx {
                if y0 == y1 {
                    break;
                }
                err += dx;
                y0 += sy;
            }
        }
    }

    /// Draw a rectangle outline
    pub fn draw_rect(&mut self, rect: Rect, color: Color) {
        let x2 = rect.x + rect.width - 1;
        let y2 = rect.y + rect.height - 1;

        self.draw_hline(rect.x, rect.y, rect.width, color);
        self.draw_hline(rect.x, y2, rect.width, color);
        self.draw_vline(rect.x, rect.y, rect.height, color);
        self.draw_vline(x2, rect.y, rect.height, color);
    }

    /// Fill a rectangle with a color
    pub fn fill_rect(&mut self, rect: Rect, color: Color) {
        let end_x = core::cmp::min(rect.x + rect.width, self.width);
        let end_y = core::cmp::min(rect.y + rect.height, self.height);

        for y in rect.y..end_y {
            for x in rect.x..end_x {
                self.set_pixel(x, y, color);
            }
        }
    }

    /// Draw a circle outline using the midpoint circle algorithm
    pub fn draw_circle(&mut self, center_x: usize, center_y: usize, radius: usize, color: Color) {
        if radius == 0 {
            self.set_pixel(center_x, center_y, color);
            return;
        }

        let (cx, cy, r) = (center_x as isize, center_y as isize, radius as isize);
        let mut x = 0;
        let mut y = r;
        let mut d = 1 - r;

        let plot_points =
            |fb: &mut Self, cx: isize, cy: isize, x: isize, y: isize, color: Color| {
                let points = [
                    (cx + x, cy + y),
                    (cx - x, cy + y),
                    (cx + x, cy - y),
                    (cx - x, cy - y),
                    (cx + y, cy + x),
                    (cx - y, cy + x),
                    (cx + y, cy - x),
                    (cx - y, cy - x),
                ];

                for (px, py) in points {
                    if px >= 0 && py >= 0 && px < fb.width as isize && py < fb.height as isize {
                        fb.set_pixel(px as usize, py as usize, color);
                    }
                }
            };

        while x <= y {
            plot_points(self, cx, cy, x, y, color);

            x += 1;
            if d < 0 {
                d += 2 * x + 1;
            } else {
                y -= 1;
                d += 2 * (x - y) + 1;
            }
        }
    }

    /// Fill a circle with a color using the midpoint circle algorithm
    pub fn fill_circle(&mut self, center_x: usize, center_y: usize, radius: usize, color: Color) {
        if radius == 0 {
            self.set_pixel(center_x, center_y, color);
            return;
        }

        let (cx, cy, r) = (center_x as isize, center_y as isize, radius as isize);
        let mut x = 0;
        let mut y = r;
        let mut d = 1 - r;

        let fill_lines = |fb: &mut Self, cx: isize, cy: isize, x: isize, y: isize, color: Color| {
            // Draw horizontal lines between the points
            if x > 0 {
                if cy + y >= 0 && cy + y < fb.height as isize {
                    fb.draw_hline(
                        (cx - x + 1) as usize,
                        (cy + y) as usize,
                        (2 * x - 1) as usize,
                        color,
                    );
                }
                if cy - y >= 0 && cy - y < fb.height as isize {
                    fb.draw_hline(
                        (cx - x + 1) as usize,
                        (cy - y) as usize,
                        (2 * x - 1) as usize,
                        color,
                    );
                }
            }

            if y > 0 {
                if cy + x >= 0 && cy + x < fb.height as isize {
                    fb.draw_hline(
                        (cx - y + 1) as usize,
                        (cy + x) as usize,
                        (2 * y - 1) as usize,
                        color,
                    );
                }
                if cy - x >= 0 && cy - x < fb.height as isize {
                    fb.draw_hline(
                        (cx - y + 1) as usize,
                        (cy - x) as usize,
                        (2 * y - 1) as usize,
                        color,
                    );
                }
            }
        };

        while x <= y {
            fill_lines(self, cx, cy, x, y, color);

            x += 1;
            if d < 0 {
                d += 2 * x + 1;
            } else {
                y -= 1;
                d += 2 * (x - y) + 1;
            }
        }
    }

    /// Swap the back buffer with the frame buffer to display the rendered content
    pub fn swap(&mut self) {
        unsafe {
            ptr::copy_nonoverlapping(self.back_buffer.as_ptr(), self.addr, self.size);
        }
    }
}

/// Global framebuffer instance
pub static FRAMEBUFFER: Mutex<Option<FrameBuffer>> = Mutex::new(None);

/// Initialize the global framebuffer
pub fn init() -> bool {
    let mut fb_lock = FRAMEBUFFER.lock();

    // Return early if already initialized
    if fb_lock.is_some() {
        return true;
    }

    // Get the framebuffer from the Limine response
    if let Some(framebuffer_response) = FRAMEBUFFER_REQUEST.get_response() {
        if let Some(framebuffer) = framebuffer_response.framebuffers().next() {
            // Create our framebuffer wrapper
            if let Some(fb) = FrameBuffer::new(&framebuffer) {
                *fb_lock = Some(fb);
                return true;
            }
        }
    }

    false
}

/// Get a reference to the global framebuffer
pub fn get() -> Option<spin::MutexGuard<'static, Option<FrameBuffer>>> {
    let guard = FRAMEBUFFER.lock();
    if guard.is_some() {
        Some(guard)
    } else {
        None
    }
}

/// Execute a function with the framebuffer
pub fn with_framebuffer<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut FrameBuffer) -> R,
{
    let mut guard = get()?;
    let fb = guard.as_mut()?;
    Some(f(fb))
}

/// Clear the screen with the specified color
pub fn clear(color: Color) {
    with_framebuffer(|fb| fb.clear(color));
}

/// Swap the back buffer with the frame buffer to display the rendered content
pub fn swap() {
    with_framebuffer(|fb| fb.swap());
}
