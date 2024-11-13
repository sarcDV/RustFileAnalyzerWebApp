// *************************************************
// ---- working with fuzzy and human hashes -----
// *************************************************
use actix_files as afs;
use actix_multipart::Multipart;
use actix_web::{web, App, Error, HttpResponse, HttpServer, Responder};
use futures_util::stream::StreamExt as _;
use ring::digest::{Context, SHA256};
use serde::Serialize;
use std::fs::{File, create_dir_all};
use std::io::{self, Read, Write};
use std::path::Path;
use md5;
use hex;
use infer;
use sanitize_filename::sanitize;
use human_hash::humanize; 
use uuid::Uuid;
use ssdeep::hash_file;

#[derive(Serialize)]
struct FileInfo {
    filesize: String,
    filetype: String,
    md5: String,
    sha256: String,
    humanhash: String,
    fuzzy_hash: String,
}

async fn save_file(mut payload: Multipart) -> Result<HttpResponse, Error> {
    let mut file_info = None;

    while let Some(Ok(mut field)) = payload.next().await {
        let content_disposition = field.content_disposition().unwrap();
        let filename = content_disposition.get_filename().unwrap();
        let filepath = format!("./uploads/{}", sanitize(filename));
        let filepath_clone = filepath.clone();

        let mut f = web::block(move || File::create(filepath)).await??;

        while let Some(chunk) = field.next().await {
            let data = chunk?;
            f = web::block(move || {
                f.write_all(&data)?;
                Ok::<_, io::Error>(f)
            })
            .await??;
        }

        file_info = Some(analyze_file(filepath_clone));
    }

    Ok(HttpResponse::Ok().json(file_info.unwrap()))
}

fn analyze_file(filepath: String) -> FileInfo {
    let metadata = std::fs::metadata(&filepath).unwrap();
    let filesize = format_size(metadata.len());

    let mut file = File::open(&filepath).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    let filetype = infer::get(&buffer).map_or("unknown".to_string(), |kind| kind.mime_type().to_string());

    let md5 = md5::compute(&buffer);
    let sha256 = sha256_digest(&buffer);

    let uuid = Uuid::new_v5(&Uuid::NAMESPACE_OID, &buffer); 
    let humanhash = humanize(&uuid, 4);

    let fuzzy_hash = hash_file(&filepath); 
    let fuzzy_hash_str = match fuzzy_hash { Ok(fh) => fh.to_string(), Err(_) => String::from("N/A"), }; 
    FileInfo {
        filesize,
        filetype,
        md5: format!("{:x}", md5),
        sha256,
        humanhash, //: "example-humanhash".to_string(),
        fuzzy_hash: fuzzy_hash_str,
    }
}

fn format_size(bytes: u64) -> String {
    let sizes = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut i = 0;
    while size >= 1024.0 && i < sizes.len() - 1 {
        size /= 1024.0;
        i += 1;
    }
    format!("{:.2} {}", size, sizes[i])
}

fn sha256_digest(bytes: &[u8]) -> String {
    let mut context = Context::new(&SHA256);
    context.update(bytes);
    let digest = context.finish();
    hex::encode(digest.as_ref())
}

async fn index() -> impl Responder {
    afs::NamedFile::open_async("./index.html").await.unwrap()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Ensure the upload directory exists
    if !Path::new("./uploads").exists() {
        create_dir_all("./uploads").expect("Failed to create upload directory");
    }

    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(index))
            .route("/upload", web::post().to(save_file))
    })
    .bind("127.0.0.1:8000")?
    .run()
    .await
}
