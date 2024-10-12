import smtplib
from email.mime.text import MIMEText

def send_verification_email(to_email, token):
    verification_link = f"http://localhost:8000/auth/verify?token={token}"
    msg = MIMEText(f"Please verify your email by clicking on the following link: {verification_link}")
    msg['Subject'] = 'Email Verification'
    msg['From'] = 'fylinde.marketplace@gmail.com'
    msg['To'] = to_email

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()  # Upgrade the connection to a secure encrypted SSL/TLS connection
        server.login('fylinde.marketplace@gmail.com', 'Chukwuemeka@2020')
        server.sendmail(msg['From'], [msg['To']], msg.as_string())

    print("Verification email sent!")
