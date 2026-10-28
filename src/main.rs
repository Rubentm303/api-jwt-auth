use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode };
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration};
use actix_web::{App, Error, error, HttpResponse, HttpServer, dev::ServiceRequest, get, post, web};
//Esto se debe manejar desde un .env
use actix_web_httpauth::{extractors::bearer::BearerAuth, middleware::HttpAuthentication};

const LLAVE: &str = "123456";


#[derive(Serialize, Deserialize, Debug)]
struct  Claims {
    iss: String,
    sub: String,
    exp: usize,
    iat: usize,
    user_id: usize
}

#[derive(Serialize, Deserialize)]
struct LoginForm {
    username: String,
    password: String
}

#[derive(Serialize, Deserialize)]
struct LoginResult {
    token: String
}

fn generate_token(iss: String, sub: String, duracion_minutos: i64, user_id: usize) -> String {
    let header = Header::new(Algorithm::HS512);
    let encoding_key = EncodingKey::from_secret(LLAVE.as_ref());

    let exp = (Utc::now() + Duration::minutes(duracion_minutos)).timestamp() as usize;
    let iat = Utc::now().timestamp() as usize;
    let my_claims = Claims {
        iss,
        sub, 
        exp,
        iat, 
        user_id
    };

    encode(&header, &my_claims, &encoding_key).unwrap()
}

fn validate_token (token: String) -> Result<Claims, jsonwebtoken::errors::Error> {
    let validation = Validation::new(Algorithm::HS512);
    let decoding_key = DecodingKey::from_secret(LLAVE.as_ref());

    let resultado = decode::<Claims>(token, &decoding_key, &validation);

    match resultado {
        Ok(c) => {
            println!("Token es Valido");
            Ok(c.claims)
        },
        Err(e) => {
            println!("Token No Valido");
            Err(e)
        }
    }
}

async fn validate(req:ServiceRequest, credentials:Option<BearerAuth>) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let Some(credentials) = credentials else {
        return Err((error::ErrorBadRequest("No se especificó el token"), req));
    };

    let token = credentials.token().to_owned();
    let resultado = validate_token(token);

    match resultado {
        Ok(claims) => {
            println!("los claims son {:?}", claims);
            return Ok(req);
        }, 
        Err(e) => {
            println!("El token no es valido {:?}", e);
            return Err((error::ErrorForbidden("No tienes acceso"), req));
        }
    }
}

#[post("/login")]
async fn login(form: web::Form<LoginForm>) -> HttpResponse {
    if form.username == "rusty" && form.password == "123456" {
        let iss = "Test Test".to_string();
        let sub = "Test".to_string();
        let duracion_minutos: i64 = 5;
        let user_id = 1;

        let token = generate_token(iss, sub, duracion_minutos, user_id);
        let respuesta = LoginResult {
            token
        };
        HttpResponse::Ok().json(respuesta)
    } else {
        HttpResponse::Unauthorized().body("Login Invalido")
    }
} 



#[get("/private")]
async fn private() -> HttpResponse {
    HttpResponse::Ok().body("Privado")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let auth = HttpAuthentication::with_fn(validate);
        App::new()
        .service(login)
        .service(
            web::scope("/admin")
            .wrap(auth)
            .service(private)
        )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
