use route_publisher::{publish, PublisherSettings};

#[tokio::main]
async fn main() -> Result<(), route_publisher::PublishError> {
    let settings = PublisherSettings::from_environment()?;
    let manifest = publish(&settings).await?;
    println!("published route bundle version={} bytes={}", manifest.version, manifest.route_size);
    Ok(())
}
