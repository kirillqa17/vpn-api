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

// ─────────────────────────────────────────────────────────────────────────────
// Notification emails: news, expiry, support reply
// Use a shared layout without the code-box.
// ─────────────────────────────────────────────────────────────────────────────

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn notification_template(
    title: &str,
    headline: &str,
    body_html: &str,
    cta_label: Option<&str>,
    cta_url: Option<&str>,
    unsubscribe_url: &str,
    unsubscribe_kind_label: &str,
) -> String {
    let cta_block = match (cta_label, cta_url) {
        (Some(label), Some(url)) => format!(
            r#"<tr><td style="padding:8px 40px 28px;text-align:center;">
              <a href="{url}" style="display:inline-block;background-color:#7C6BFF;color:#ffffff;text-decoration:none;font-size:14px;font-weight:600;padding:14px 32px;border-radius:12px;">{label}</a>
            </td></tr>"#,
            url = url, label = html_escape(label)
        ),
        _ => String::new(),
    };

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
<table role="presentation" width="520" cellpadding="0" cellspacing="0" style="background-color:#141414;border-radius:16px;overflow:hidden;border:1px solid #1e1e1e;">

<tr><td style="padding:36px 40px 16px;text-align:center;">
  <img src="https://svoiweb.ru/icon-192.png" alt="SvoiVPN" width="56" height="56" style="border-radius:14px;display:inline-block;" />
  <div style="margin-top:12px;font-size:22px;font-weight:600;color:#ffffff;letter-spacing:1px;">SvoiVPN</div>
</td></tr>

<tr><td style="padding:0 40px 8px;text-align:center;">
  <div style="font-size:18px;color:#ffffff;font-weight:600;">{headline}</div>
</td></tr>

<tr><td style="padding:8px 40px;">
  <div style="height:1px;background-color:#1e1e1e;"></div>
</td></tr>

<tr><td style="padding:24px 40px 8px;">
  <div style="font-size:14px;color:#c4c4c4;line-height:1.65;">{body_html}</div>
</td></tr>

{cta_block}

<tr><td style="padding:0 40px;">
  <div style="height:1px;background-color:#1e1e1e;"></div>
</td></tr>

<tr><td style="padding:20px 40px 16px;text-align:center;">
  <a href="https://svoiweb.ru" style="font-size:12px;color:#7C6BFF;text-decoration:none;">svoiweb.ru</a>
  <span style="color:#333;margin:0 8px;">&#8226;</span>
  <a href="https://t.me/svoivless_help_bot" style="font-size:12px;color:#7C6BFF;text-decoration:none;">Поддержка</a>
</td></tr>

<tr><td style="padding:0 40px 28px;text-align:center;">
  <div style="font-size:11px;color:#555;line-height:1.5;">
    Вы получили это письмо потому что подписаны на {unsubscribe_kind_label}.<br>
    <a href="{unsubscribe_url}" style="color:#666;text-decoration:underline;">Отписаться от этого типа уведомлений</a>
  </div>
</td></tr>

</table>
</td></tr>
</table>
</body>
</html>"#,
        title = html_escape(title),
        headline = html_escape(headline),
        body_html = body_html,
        cta_block = cta_block,
        unsubscribe_url = unsubscribe_url,
        unsubscribe_kind_label = unsubscribe_kind_label,
    )
}

pub async fn send_news_email(
    to: &str,
    headline: &str,
    body_text: &str,
    unsubscribe_url: &str,
) -> Result<(), String> {
    // Convert plain body to <p> blocks, escape HTML
    let body_html = body_text
        .split("\n\n")
        .map(|p| format!("<p style=\"margin:0 0 12px;\">{}</p>", html_escape(p).replace('\n', "<br>")))
        .collect::<Vec<_>>()
        .join("");

    let html = notification_template(
        "Новости SvoiVPN",
        headline,
        &body_html,
        Some("Открыть svoiweb.ru"),
        Some("https://svoiweb.ru"),
        unsubscribe_url,
        "новости SvoiVPN",
    );
    send_email(to, &format!("📰 {}", headline), &html).await
}

pub async fn send_expiry_email(
    to: &str,
    kind: &str, // "3_days" | "1_day" | "expired"
    plan: &str,
    days_left: i64,
    unsubscribe_url: &str,
) -> Result<(), String> {
    let (headline, body_html, subject) = match kind {
        "3_days" => (
            "Подписка истекает через 3 дня",
            format!("Ваша подписка на тариф <b>{}</b> закончится через <b>3 дня</b>.<br><br>Чтобы не потерять доступ к VPN, продлите её сейчас в боте или на сайте.", html_escape(plan)),
            "⏰ Подписка SvoiVPN истекает через 3 дня".to_string(),
        ),
        "1_day" => (
            "Подписка истекает завтра",
            format!("Ваша подписка на тариф <b>{}</b> закончится <b>завтра</b>.<br><br>Продлите её сейчас, чтобы избежать перерыва в работе VPN.", html_escape(plan)),
            "⏰ Подписка SvoiVPN истекает завтра".to_string(),
        ),
        "expired" => (
            "Подписка закончилась",
            format!("Срок действия подписки на тариф <b>{}</b> истёк {} назад. VPN отключён.<br><br>Возобновите подписку в один клик.", html_escape(plan), if days_left.abs() == 1 {"1 день".to_string()} else {format!("{} дн.", days_left.abs())}),
            "❌ Подписка SvoiVPN закончилась".to_string(),
        ),
        _ => return Err(format!("Unknown expiry kind: {}", kind)),
    };

    let html = notification_template(
        "Подписка SvoiVPN",
        headline,
        &body_html,
        Some("Продлить подписку"),
        Some("https://svoiweb.ru"),
        unsubscribe_url,
        "уведомления о подписке",
    );
    send_email(to, &subject, &html).await
}

pub async fn send_support_reply_email(
    to: &str,
    admin_message: &str,
    unsubscribe_url: &str,
) -> Result<(), String> {
    let body_html = format!(
        "Оператор SvoiVPN ответил на ваш запрос в поддержке:<br><br>\
        <div style=\"padding:14px 16px;background-color:#1a1a2e;border-left:3px solid #7C6BFF;border-radius:8px;color:#e0e0e0;\">{}</div>\
        <br>Откройте чат на сайте, чтобы продолжить диалог.",
        html_escape(admin_message).replace('\n', "<br>")
    );

    let html = notification_template(
        "Ответ от поддержки",
        "Новый ответ от оператора",
        &body_html,
        Some("Открыть чат поддержки"),
        Some("https://svoiweb.ru"),
        unsubscribe_url,
        "ответы поддержки на сайте",
    );
    send_email(to, "💬 Ответ от поддержки SvoiVPN", &html).await
}
