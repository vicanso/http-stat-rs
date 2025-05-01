use http_stat::{request, HttpRequest};

#[tokio::main]
async fn main() {
    let stat = request("http://www.baidu.com/".try_into().unwrap()).await;
    // println!("{:?}", stat);
    println!("{}", stat);
}
