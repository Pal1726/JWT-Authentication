from django.core.mail import EmailMessage
import os

class Util:
    @staticmethod
    def send_email(data):
        print(f"Sending email to {data['to_email']} with subject {data['subject']}")
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            from_email=os.environ.get('EMAIL_FROM'),
            to=[data['to_email']]
        )
        
        try:
            email.send()
            print("Email sent successfully!")
        except Exception as e:
            print(f"Error sending email: {e}")
