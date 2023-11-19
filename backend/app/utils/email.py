import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from jinja2 import Environment, FileSystemLoader
from app.redis.base import r

class Mail:
    @staticmethod
    def verification_email(recipient, body):
        r.set(recipient, 'sending')
        message = MIMEMultipart("alternative")
        message["Subject"] = body.get('subject')
        message["From"] = os.getenv('MAIL_FROM')
        message["To"] = recipient

        file_loader = FileSystemLoader('app/templates/email')
        env = Environment(loader=file_loader)
        template = env.get_template('verification_email.html')
        html = template.render(subject=body.get('subject'), token=body.get('token'))
        mimehtml = MIMEText(html, 'html')
        message.attach(mimehtml)
        with smtplib.SMTP(os.getenv('MAIL_SERVER'), 2525) as server:
            server.login(os.getenv('MAIL_USERNAME'), os.getenv('MAIL_PASSWORD'))
            server.sendmail(
                os.getenv('MAIL_FROM'), recipient, message.as_string()
            )
        r.delete(recipient)

    @staticmethod
    def password_reset_email(recipient, body):
        message = MIMEMultipart("alternative")
        message["Subject"] = body.get('subject')
        message["From"] = os.getenv('MAIL_FROM')
        message["To"] = recipient

        file_loader = FileSystemLoader('app/templates/email')
        env = Environment(loader=file_loader)
        template = env.get_template('password_reset_email.html')
        html = template.render(subject=body.get('subject'), token=body.get('token'))
        mimehtml = MIMEText(html, 'html')
        message.attach(mimehtml)
        with smtplib.SMTP(os.getenv('MAIL_SERVER'), 2525) as server:
            server.login(os.getenv('MAIL_USERNAME'), os.getenv('MAIL_PASSWORD'))
            server.sendmail(
                os.getenv('MAIL_FROM'), recipient, message.as_string()
            )