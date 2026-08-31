# Email Alerts - Setup Guide

Sentinel-HIDS can email you a summary when it finds high or critical issues.
For security, NO password is stored in this project. Each person sets up their
own email and their own app password on their own machine.

## Steps (each user does this themselves)

1. Install the mail sender:
   sudo apt update
   sudo apt install -y msmtp msmtp-mta ca-certificates

2. Get a Gmail App Password (NOT your normal password):
   - Turn ON 2-Step Verification in your Google account.
   - Go to: Google Account > Security > 2-Step Verification > App passwords.
   - Create one, name it "Sentinel-HIDS", and copy the 16 characters.

3. Create the file ~/.msmtprc with this content (use YOUR email and app password):

   defaults
   auth           on
   tls            on
   tls_trust_file /etc/ssl/certs/ca-certificates.crt
   logfile        ~/.msmtp.log

   account        gmail
   host           smtp.gmail.com
   port           587
   from           YOUR_EMAIL@gmail.com
   user           YOUR_EMAIL@gmail.com
   password       YOUR_16_CHAR_APP_PASSWORD

   account default : gmail

4. Lock the file so only you can read it:
   chmod 600 ~/.msmtprc

5. Give root its own copy (the tool runs with sudo, so root must read it):
   sudo cp ~/.msmtprc /root/.msmtprc
   sudo chmod 600 /root/.msmtprc

6. Put your email in config/hids.conf on this line:
   NOTIFY_EMAIL_TO="YOUR_EMAIL@gmail.com"

7. Test it:
   printf 'Subject: test\n\nWorks.\n' | msmtp YOUR_EMAIL@gmail.com
   Check your inbox and spam folder.

## Notes
- Sends ONE summary email per run, only for high/critical findings.
- A clean scan sends nothing.
- To turn email off: set NOTIFY_ENABLED=0 in config/hids.conf.
