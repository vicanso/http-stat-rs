use http_stat::request;

#[tokio::main]
async fn main() {
    let stat = request("https://www.baidu.com/".try_into().unwrap()).await;
    // println!("{:?}", stat);
    println!("{stat}");
}
