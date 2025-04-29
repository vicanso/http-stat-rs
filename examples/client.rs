use http_stat::{request, HttpRequest};

#[tokio::main]
async fn main() {
    let req = HttpRequest {
        uri: "https://www.baidu.com/".try_into().unwrap(),
        ..Default::default()
    };

    let stat = request(req).await.unwrap();
    println!("{:?}", stat);
}
