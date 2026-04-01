use lettre::{
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use log::{error, info};
use std::sync::OnceLock;

static MAILER: OnceLock<AsyncSmtpTransport<Tokio1Executor>> = OnceLock::new();
static SMTP_FROM: OnceLock<String> = OnceLock::new();

pub fn init() {
    let host = std::env::var("SMTP_HOST").unwrap_or_else(|_| "smtp.yandex.ru".to_string());
    let port: u16 = std::env::var("SMTP_PORT")
        .unwrap_or_else(|_| "465".to_string())
        .parse()
        .unwrap_or(465);
    let user = std::env::var("SMTP_USER").expect("SMTP_USER must be set");
    let password = std::env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");
    let from = std::env::var("SMTP_FROM")
        .unwrap_or_else(|_| format!("SvoiVPN <{}>", user.clone()));

    let creds = Credentials::new(user, password);

    let mailer = if port == 465 {
        // SMTPS (implicit TLS)
        AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
            .expect("Failed to create SMTP transport")
            .port(port)
            .credentials(creds)
            .build()
    } else {
        // STARTTLS (port 25 or 587)
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
            .expect("Failed to create SMTP transport")
            .port(port)
            .credentials(creds)
            .build()
    };

    MAILER.set(mailer).expect("SMTP already initialized");
    SMTP_FROM.set(from).expect("SMTP_FROM already initialized");
    info!("[email] SMTP initialized: {}:{}", host, port);
}

async fn send_email(to: &str, subject: &str, body: &str) -> Result<(), String> {
    let mailer = MAILER.get().ok_or("SMTP not initialized")?;
    let from = SMTP_FROM.get().ok_or("SMTP_FROM not initialized")?;

    let email = Message::builder()
        .from(from.parse().map_err(|e| format!("Invalid from: {}", e))?)
        .to(to.parse().map_err(|e| format!("Invalid to: {}", e))?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_string())
        .map_err(|e| format!("Failed to build email: {}", e))?;

    match mailer.send(email).await {
        Ok(_) => {
            info!("[email] Sent to {}: {}", to, subject);
            Ok(())
        }
        Err(e) => {
            error!("[email] Failed to send to {}: {}", to, e);
            Err(format!("SMTP error: {}", e))
        }
    }
}

pub async fn send_verification_code(to: &str, code: &str) -> Result<(), String> {
    let body = format!(
        "Ваш код подтверждения: {}\n\nКод действителен 10 минут.\nЕсли вы не регистрировались в SvoiVPN, проигнорируйте это письмо.",
        code
    );
    send_email(to, "Код подтверждения SvoiVPN", &body).await
}

pub async fn send_reset_code(to: &str, code: &str) -> Result<(), String> {
    let body = format!(
        "Ваш код для сброса пароля: {}\n\nКод действителен 10 минут.\nЕсли вы не запрашивали сброс пароля, проигнорируйте это письмо.",
        code
    );
    send_email(to, "Сброс пароля SvoiVPN", &body).await
}
