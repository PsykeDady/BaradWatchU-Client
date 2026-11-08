//! Tray icons drawn at runtime (no image assets): a coloured "eye" per state.
use crate::model::Health;

const SIZE: u32 = 64;

fn colour(health: Health) -> [u8; 3] {
    match health {
        Health::Ok => [0x2e, 0x7d, 0x32],          // green
        Health::NoAudit => [0x45, 0x6b, 0x8a],     // slate blue: running, nothing audited
        Health::Anomalies => [0xef, 0x8f, 0x00],   // amber
        Health::Critical => [0xc6, 0x28, 0x28],    // red
        Health::Attention => [0x15, 0x65, 0xc0],   // blue: a decision is needed
        Health::Unreachable => [0x75, 0x75, 0x75], // grey
    }
}

/// Coverage of a disc of `radius` at pixel (x, y), with a one-pixel soft edge.
fn disc(x: f32, y: f32, radius: f32) -> f32 {
    let centre = SIZE as f32 / 2.0;
    let distance = ((x - centre).powi(2) + (y - centre).powi(2)).sqrt();
    (radius + 0.5 - distance).clamp(0.0, 1.0)
}

pub fn rgba(health: Health) -> Vec<u8> {
    let [r, g, b] = colour(health);
    let mut pixels = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let (fx, fy) = (x as f32 + 0.5, y as f32 + 0.5);
            let outer = disc(fx, fy, 30.0);
            let white = disc(fx, fy, 17.0);
            // An unreachable agent shows an empty eye (no pupil).
            let pupil = if health == Health::Unreachable {
                0.0
            } else {
                disc(fx, fy, 8.5)
            };
            let mix = |base: u8, light: u8| {
                let value = base as f32 * (1.0 - white) + light as f32 * white;
                (value * (1.0 - pupil) + base as f32 * 0.35 * pupil) as u8
            };
            pixels.extend_from_slice(&[
                mix(r, 0xff),
                mix(g, 0xff),
                mix(b, 0xff),
                (outer * 255.0) as u8,
            ]);
        }
    }
    pixels
}

pub fn icon(health: Health) -> Option<tray_icon::Icon> {
    tray_icon::Icon::from_rgba(rgba(health), SIZE, SIZE).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icons_differ_per_state_and_have_transparent_corners() {
        let states = [
            Health::Ok,
            Health::NoAudit,
            Health::Anomalies,
            Health::Critical,
            Health::Attention,
            Health::Unreachable,
        ];
        let images = states.map(rgba);
        for (index, image) in images.iter().enumerate() {
            assert_eq!(image.len(), (SIZE * SIZE * 4) as usize);
            assert_eq!(image[3], 0, "corner must be transparent");
            for other in &images[index + 1..] {
                assert_ne!(image, other);
            }
        }
    }
}
