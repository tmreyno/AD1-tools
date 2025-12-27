use serde::Serialize;
use std::path::Path;

use crate::ad1;

#[derive(Serialize)]
pub struct ContainerInfo {
    pub container: String,
    pub ad1: Option<ad1::Ad1Info>,
    pub note: Option<String>,
}

enum ContainerKind {
    Ad1,
    L01,
}

pub fn info(path: &str, include_tree: bool) -> Result<ContainerInfo, String> {
    let kind = detect_container(path)?;
    match kind {
        ContainerKind::Ad1 => {
            let info = ad1::info(path, include_tree)?;
            Ok(ContainerInfo {
                container: "AD1".to_string(),
                ad1: Some(info),
                note: None,
            })
        }
        ContainerKind::L01 => Ok(ContainerInfo {
            container: "L01".to_string(),
            ad1: None,
            note: Some("L01/Lx01 support is not implemented yet.".to_string()),
        }),
    }
}

pub fn verify(path: &str, algorithm: &str) -> Result<Vec<ad1::VerifyEntry>, String> {
    match detect_container(path)? {
        ContainerKind::Ad1 => ad1::verify(path, algorithm),
        ContainerKind::L01 => Err("L01/Lx01 verification is not implemented yet.".to_string()),
    }
}

pub fn extract(path: &str, output_dir: &str) -> Result<(), String> {
    match detect_container(path)? {
        ContainerKind::Ad1 => ad1::extract(path, output_dir),
        ContainerKind::L01 => Err("L01/Lx01 extraction is not implemented yet.".to_string()),
    }
}

fn detect_container(path: &str) -> Result<ContainerKind, String> {
    let path_obj = Path::new(path);
    if !path_obj.exists() {
        return Err(format!("Input file not found: {path}"));
    }

    let lower = path.to_lowercase();
    if lower.ends_with(".l01") || lower.ends_with(".lx01") {
        return Ok(ContainerKind::L01);
    }

    if ad1::is_ad1(path)? {
        return Ok(ContainerKind::Ad1);
    }

    Err("Unsupported or unrecognized logical container.".to_string())
}
