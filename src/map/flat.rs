//! Static equirectangular 2D world map renderer.

use super::earth::{earth_bitmap, EARTH_HEIGHT, EARTH_WIDTH};
use super::{GeoPoint, MapCell};

/// Scale the earth bitmap to `width` × `height` and plot located IPs.
pub fn render_flat(width: usize, height: usize, points: &[&GeoPoint]) -> Vec<Vec<MapCell>> {
    if width == 0 || height == 0 {
        return vec![vec![MapCell::Empty]];
    }

    let map = earth_bitmap();
    let mut cells = vec![vec![MapCell::Ocean; width]; height];

    for y in 0..height {
        let src_y = ((y as f64 / height as f64) * EARTH_HEIGHT as f64).floor() as usize;
        let src_y = src_y.min(EARTH_HEIGHT - 1);
        let row = map[src_y];
        for x in 0..width {
            let src_x = ((x as f64 / width as f64) * EARTH_WIDTH as f64).floor() as usize;
            let src_x = src_x.min(EARTH_WIDTH - 1);
            let ch = row.chars().nth(src_x).unwrap_or(' ');
            cells[y][x] = if ch == ' ' {
                MapCell::Ocean
            } else {
                MapCell::Land
            };
        }
    }

    for p in points {
        if !p.valid {
            continue;
        }
        // Longitude −180…180 → x, latitude 90…−90 → y
        let x_f = ((p.longitude + 180.0) / 360.0) * width as f64;
        let y_f = ((90.0 - p.latitude) / 180.0) * height as f64;
        let x = x_f.floor() as isize;
        let y = y_f.floor() as isize;
        if x >= 0 && y >= 0 && (x as usize) < width && (y as usize) < height {
            cells[y as usize][x as usize] = MapCell::Marker;
        }
    }

    cells
}
