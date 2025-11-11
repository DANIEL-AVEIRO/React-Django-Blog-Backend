from django.core.mail import EmailMultiAlternatives
from django.template import Template, Context
import random


def generate_otp(length=6):
    return "".join([str(random.randint(0, 9)) for _ in range(length)])


def send_otp_email(user_email, otp_code):
    html_template = """
    <div style="font-family: Arial, sans-serif;max-width: 600px;margin:0 auto; padding:20px; border:1px solid #ddd;border-radius: 8px;background-color: #000;color:#fff;">
        <h2 style="color: #fff;text-align: center;">Verify Your Email Address</h2>
        <p style="font-size: 16px;color:#ccc;">Dear User,</p>
        <p style="font-size: 16px;color:#ccc;">To complete your registration, please use this verification code:</p>
        <div style="text-align: center;margin:20px 0;">
            <span style="display:inline-block;font-size:24px;font-weight:bold;color:#000;padding:10px 20px;border:1px solid #fff;border-radius:5px;background-color:#fff;">
                {{ otp_code }}
            </span>
        </div>
        <p style="font-size: 16px;color:#ccc;">This code is valid for 15 minutes.</p>
        <footer style="margin-top:20px;text-align:center;font-size:14px;color:#666;">
            <p>Thank you,<br>BookWorm Team</p>
        </footer>
    </div>
    """
    template = Template(html_template)
    context = Context({"otp_code": otp_code})
    html_content = template.render(context)

    subject = "Verify Your Email Address"
    msg = EmailMultiAlternatives(subject, "", None, [user_email])
    msg.attach_alternative(html_content, "text/html")
    msg.send()
