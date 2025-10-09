use actix_web::{get, post, web, App, HttpServer, Responder};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct User { 
    id: u32, 
    name: String,
}

#[get("/")]
async fn root() -> impl Responder {
    "Hello, world!"
}

#[get("/signup")]
async fn get_user(path: web::Path<u32>) -> impl Responder {
    let user_id = path.into_inner();
    web::Json(User {
        id: user_id,
        name: "Ayush".to_string(),
    }) 
    
    // hit mpc rounds 1 (end point 1 round 1 , round 2)
}

#[derive(Deserialize)]
struct CreateUser {
    name: String,
}

#[post("/user")]
async fn create_user(payload: web::Json<CreateUser>) -> impl Responder {
    let new_user = User {
        id: 1,
        name: payload.name.clone(),
    };
    web::Json(new_user)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🚀 Server running at http://127.0.0.1:8080");
    
    HttpServer::new(|| {
        App::new()
            .service(root)
            .service(get_user)
            .service(create_user)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
