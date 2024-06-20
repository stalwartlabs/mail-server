/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of Stalwart Mail Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
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
