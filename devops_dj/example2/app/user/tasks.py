from celery import shared_task
from celery.utils.log import get_task_logger
from core.mailer import BrandSecureMailSend
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes


logger = get_task_logger(__name__)


@shared_task
def send_mail_forgot_password(name, email):
    mail_id = email
    mail_data = {
        'name': name,
        'email': urlsafe_base64_encode(force_bytes(email))
        }
    mail_class = BrandSecureMailSend('FPE', [mail_id])
    mail_response = mail_class.mailsend(mail_data)
    print('mail_response...', mail_response)
    return True


@shared_task
def send_mail_for_account_activation(email, name, domain, uid, token):
    mail_id = email
    mail_data = {
        'name': name,
        'domain': domain,
        'uid': uid,
        'token': token
        }
    mail_class = BrandSecureMailSend('UEV', [mail_id])
    mail_response = mail_class.mailsend(mail_data)
    print('mail_response...', mail_response)
    return True
