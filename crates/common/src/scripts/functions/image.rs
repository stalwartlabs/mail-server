/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use sieve::{runtime::Variable, Context};

pub fn fn_img_metadata<'x>(ctx: &'x Context<'x>, v: Vec<Variable>) -> Variable {
    ctx.message()
        .part(ctx.part())
        .map(|p| p.contents())
        .and_then(|bytes| {
            let arg = v[1].to_string();
            match arg.as_ref() {
                "type" => imagesize::image_type(bytes).ok().map(|t| {
                    Variable::from(match t {
                        imagesize::ImageType::Aseprite => "aseprite",
                        imagesize::ImageType::Bmp => "bmp",
                        imagesize::ImageType::Dds => "dds",
                        imagesize::ImageType::Exr => "exr",
                        imagesize::ImageType::Farbfeld => "farbfeld",
                        imagesize::ImageType::Gif => "gif",
                        imagesize::ImageType::Hdr => "hdr",
                        imagesize::ImageType::Heif(_) => "heif",
                        imagesize::ImageType::Ico => "ico",
                        imagesize::ImageType::Jpeg => "jpeg",
                        imagesize::ImageType::Jxl => "jxl",
                        imagesize::ImageType::Ktx2 => "ktx2",
                        imagesize::ImageType::Png => "png",
                        imagesize::ImageType::Pnm => "pnm",
                        imagesize::ImageType::Psd => "psd",
                        imagesize::ImageType::Qoi => "qoi",
                        imagesize::ImageType::Tga => "tga",
                        imagesize::ImageType::Tiff => "tiff",
                        imagesize::ImageType::Vtf => "vtf",
                        imagesize::ImageType::Webp => "webp",
                        imagesize::ImageType::Ilbm => "ilbm",
                        _ => "unknown",
                    })
                }),
                "width" => imagesize::blob_size(bytes)
                    .ok()
                    .map(|s| Variable::Integer(s.width as i64)),
                "height" => imagesize::blob_size(bytes)
                    .ok()
                    .map(|s| Variable::Integer(s.height as i64)),
                "area" => imagesize::blob_size(bytes)
                    .ok()
                    .map(|s| Variable::Integer(s.width.saturating_mul(s.height) as i64)),
                "dimension" => imagesize::blob_size(bytes)
                    .ok()
                    .map(|s| Variable::Integer(s.width.saturating_add(s.height) as i64)),
                _ => None,
            }
        })
        .unwrap_or_default()
}
