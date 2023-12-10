import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Environment, FileSystemLoader

from app.models_cassandra.users import EmailInProcess

class Mail:
    @staticmethod
    def email_verification(recipient, subject, code):
        EmailInProcess.create(
            task_source = "email-verification",
            email = recipient
        )
        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = os.getenv('MAIL_FROM')
            message["To"] = recipient

            file_loader = FileSystemLoader('app/templates/email')
            env = Environment(loader=file_loader)
            template = env.get_template('verification-email.html')
            html = template.render(subject=subject, code=code)
            mimehtml = MIMEText(html, 'html')
            message.attach(mimehtml)
            with smtplib.SMTP(os.getenv('MAIL_SERVER'), 2525) as server:
                server.login(os.getenv('MAIL_USERNAME'), os.getenv('MAIL_PASSWORD'))
                server.sendmail(
                    os.getenv('MAIL_FROM'), recipient, message.as_string()
                )
        except Exception as e:
            print(e)
        finally:
            EmailInProcess(
                task_source = "email-verification",
                email = recipient
            ).delete()


    @staticmethod
    def password_reset_email(recipient, body):
        EmailInProcess.create(
            task_source = "password-reset",
            email = recipient
        )
        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = body.get('subject')
            message["From"] = os.getenv('MAIL_FROM')
            message["To"] = recipient

            file_loader = FileSystemLoader('app/templates/email')
            env = Environment(loader=file_loader)
            template = env.get_template('password-reset-email.html')
            html = template.render(subject=body.get('subject'), token=body.get('token'))
            mimehtml = MIMEText(html, 'html')
            message.attach(mimehtml)
            with smtplib.SMTP(os.getenv('MAIL_SERVER'), 2525) as server:
                server.login(os.getenv('MAIL_USERNAME'), os.getenv('MAIL_PASSWORD'))
                server.sendmail(
                    os.getenv('MAIL_FROM'), recipient, message.as_string()
                )
        except Exception as e:
            print(e)
        finally:
            EmailInProcess(
                task_source = "password-reset",
                email = recipient
            ).delete()