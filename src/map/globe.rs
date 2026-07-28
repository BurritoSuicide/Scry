//! Orthographic 3D ASCII globe renderer.
//!
//! Projection and density sampling adapted from
//! [SecKC-MHN-Globe](https://github.com/n0xa/SecKC-MHN-Globe) (BSD-2-Clause).

use super::earth::sample_earth_at;
use super::{GeoPoint, MapCell};

/// Render a rotating globe of `width` × `height` cells.
///
/// `rotation` is in radians. `aspect_ratio` is character height/width (default 2.0).
pub fn render_globe(
    width: usize,
    height: usize,
    rotation: f64,
    aspect_ratio: f64,
    points: &[&GeoPoint],
) -> Vec<Vec<MapCell>> {
    if width == 0 || height == 0 {
        return vec![vec![MapCell::Empty]];
    }

    let aspect = if aspect_ratio <= 0.0 {
        2.0
    } else {
        aspect_ratio
    };
    let radius = ((width as f64) / 2.5)
        .min((height as f64) * aspect / 2.5)
        .max(1.0);

    let mut cells = vec![vec![MapCell::Empty; width]; height];
    let mut markers = vec![vec![false; width]; height];

    for p in points {
        if !p.valid {
            continue;
        }
        if let Some((x, y)) = project_3d_to_2d(
            p.latitude,
            p.longitude,
            rotation,
            width,
            height,
            radius,
            aspect,
        ) {
            if x < width && y < height {
                markers[y][x] = true;
            }
        }
    }

    let mut density = vec![vec![0.0f64; width]; height];
    let center_x = width as f64 / 2.0;
    let center_y = height as f64 / 2.0;

    for y in 0..height {
        for x in 0..width {
            let dx = x as f64 - center_x;
            let dy = (y as f64 - center_y) * aspect;
            let distance = (dx * dx + dy * dy).sqrt();

            if distance <= radius {
                let nx = dx / radius;
                let ny = dy / radius;
                let nz_sq = 1.0 - nx * nx - ny * ny;
                if nz_sq >= 0.0 {
                    let nz = nz_sq.sqrt();
                    let lat = ny.asin() * 180.0 / std::f64::consts::PI;
                    let mut lon =
                        nx.atan2(nz) * 180.0 / std::f64::consts::PI + rotation * 180.0 / std::f64::consts::PI;
                    while lon < -180.0 {
                        lon += 360.0;
                    }
                    while lon > 180.0 {
                        lon -= 360.0;
                    }

                    let earth = sample_earth_at(lat, lon);
                    if earth != ' ' {
                        let contrib = match earth {
                            '#' => 1.0,
                            '.' => 0.6,
                            _ => 0.8,
                        };
                        density[y][x] += contrib;
                        for oy in -1..=1 {
                            for ox in -1..=1 {
                                let nx2 = x as isize + ox;
                                let ny2 = y as isize + oy;
                                if nx2 >= 0
                                    && ny2 >= 0
                                    && (nx2 as usize) < width
                                    && (ny2 as usize) < height
                                {
                                    density[ny2 as usize][nx2 as usize] += 0.05;
                                }
                            }
                        }
                    } else {
                        // Ocean inside the disk.
                        if density[y][x] == 0.0 {
                            density[y][x] = -1.0;
                        }
                    }
                }
            }

            if distance > radius - 0.5 && distance < radius + 0.5 {
                density[y][x] += 0.2;
            }
        }
    }

    for y in 0..height {
        for x in 0..width {
            let d = density[y][x];
            cells[y][x] = if d < 0.0 {
                MapCell::Ocean
            } else if d > 0.3 {
                MapCell::Land
            } else if d > 0.1 {
                MapCell::Coast
            } else if d > 0.0 {
                MapCell::Ocean
            } else {
                MapCell::Empty
            };

            if markers[y][x] {
                cells[y][x] = MapCell::Marker;
            }
        }
    }

    cells
}

fn project_3d_to_2d(
    lat: f64,
    lon: f64,
    rotation: f64,
    width: usize,
    height: usize,
    radius: f64,
    aspect: f64,
) -> Option<(usize, usize)> {
    let mut adjusted_lon = -lon + 90.0;
    adjusted_lon = (adjusted_lon + 180.0).rem_euclid(360.0) - 180.0;

    let lat_rad = lat * std::f64::consts::PI / 180.0;
    let lon_rad = (adjusted_lon + rotation * 180.0 / std::f64::consts::PI) * std::f64::consts::PI / 180.0;

    let x = lat_rad.cos() * lon_rad.cos();
    let y = lat_rad.sin();
    let z = lat_rad.cos() * lon_rad.sin();

    if z < 0.0 {
        return None;
    }

    let screen_x = (x * radius + width as f64 / 2.0).round() as isize;
    let screen_y = (-y * radius / aspect + height as f64 / 2.0).round() as isize;

    if screen_x < 0 || screen_y < 0 {
        return None;
    }
    let sx = screen_x as usize;
    let sy = screen_y as usize;
    if sx >= width || sy >= height {
        return None;
    }
    Some((sx, sy))
}
