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
        AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
            .expect("Failed to create SMTP transport")
            .port(port)
            .credentials(creds)
            .build()
    } else {
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

async fn send_email(to: &str, subject: &str, html_body: &str) -> Result<(), String> {
    let mailer = MAILER.get().ok_or("SMTP not initialized")?;
    let from = SMTP_FROM.get().ok_or("SMTP_FROM not initialized")?;

    let email = Message::builder()
        .from(from.parse().map_err(|e| format!("Invalid from: {}", e))?)
        .to(to.parse().map_err(|e| format!("Invalid to: {}", e))?)
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(html_body.to_string())
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

fn email_template(title: &str, code: &str, message: &str, footer_note: &str) -> String {
    format!(r#"<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
</head>
<body style="margin:0;padding:0;background-color:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#0a0a0a;padding:40px 20px;">
<tr><td align="center">
<table role="presentation" width="460" cellpadding="0" cellspacing="0" style="background-color:#141414;border-radius:16px;overflow:hidden;border:1px solid #1e1e1e;">

<!-- Logo -->
<tr><td style="padding:36px 40px 20px;text-align:center;">
  <img src="https://svoiweb.ru/icon-192.png" alt="SvoiVPN" width="56" height="56" style="border-radius:14px;display:inline-block;" />
  <div style="margin-top:12px;font-size:22px;font-weight:600;color:#ffffff;letter-spacing:1px;">SvoiVPN</div>
</td></tr>

<!-- Title -->
<tr><td style="padding:4px 40px 24px;text-align:center;">
  <div style="font-size:16px;color:#9a9a9a;">{title}</div>
</td></tr>

<!-- Divider -->
<tr><td style="padding:0 40px;">
  <div style="height:1px;background-color:#1e1e1e;"></div>
</td></tr>

<!-- Message -->
<tr><td style="padding:28px 40px 8px;text-align:center;">
  <div style="font-size:14px;color:#b0b0b0;line-height:1.6;">{message}</div>
</td></tr>

<!-- Code -->
<tr><td style="padding:16px 40px 28px;text-align:center;">
  <div style="display:inline-block;background-color:#1a1a2e;border:1px solid #7C6BFF;border-radius:12px;padding:16px 40px;">
    <span style="font-size:32px;font-weight:700;color:#7C6BFF;letter-spacing:8px;font-family:'Courier New',monospace;">{code}</span>
  </div>
</td></tr>

<!-- Timer -->
<tr><td style="padding:0 40px 28px;text-align:center;">
  <div style="font-size:13px;color:#666;">&#9202; Код действителен <strong style="color:#9a9a9a;">10 минут</strong></div>
</td></tr>

<!-- Divider -->
<tr><td style="padding:0 40px;">
  <div style="height:1px;background-color:#1e1e1e;"></div>
</td></tr>

<!-- Footer -->
<tr><td style="padding:24px 40px 16px;text-align:center;">
  <div style="font-size:12px;color:#555;line-height:1.5;">{footer_note}</div>
</td></tr>

<tr><td style="padding:0 40px 28px;text-align:center;">
  <a href="https://svoiweb.ru" style="font-size:12px;color:#7C6BFF;text-decoration:none;">svoiweb.ru</a>
  <span style="color:#333;margin:0 8px;">&#8226;</span>
  <a href="https://t.me/svoivless_support_bot" style="font-size:12px;color:#7C6BFF;text-decoration:none;">Поддержка</a>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>"#,
        title = title,
        code = code,
        message = message,
        footer_note = footer_note,
    )
}

pub async fn send_verification_code(to: &str, code: &str) -> Result<(), String> {
    let html = email_template(
        "Подтверждение регистрации",
        code,
        "Для завершения регистрации введите код подтверждения в приложении:",
        "Если вы не регистрировались в SvoiVPN, просто проигнорируйте это письмо.",
    );
    send_email(to, "Код подтверждения SvoiVPN", &html).await
}

pub async fn send_reset_code(to: &str, code: &str) -> Result<(), String> {
    let html = email_template(
        "Сброс пароля",
        code,
        "Вы запросили сброс пароля. Введите этот код в приложении:",
        "Если вы не запрашивали сброс пароля, просто проигнорируйте это письмо. Ваш аккаунт в безопасности.",
    );
    send_email(to, "Сброс пароля SvoiVPN", &html).await
}

pub async fn send_test_email(to: &str) -> Result<(), String> {
    let html = email_template(
        "Тестовое письмо",
        "123456",
        "Это тестовое письмо для проверки нового дизайна. Так будут выглядеть все письма от SvoiVPN:",
        "Это тестовое сообщение. Никаких действий не требуется.",
    );
    send_email(to, "Тестовое письмо SvoiVPN", &html).await
}
