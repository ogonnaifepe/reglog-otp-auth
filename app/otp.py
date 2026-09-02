import random
import string
from datetime import datetime, timedelta
from app.database import db
from app.config import Config
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

logger = logging.getLogger(__name__)

class OTPService:
    @staticmethod
    def generate_otp(length=6):
        """Generate a random numeric OTP"""
        return ''.join(random.choices(string.digits, k=length))
    
    @staticmethod
    def send_email(email, otp_code, purpose):
        """Send OTP via email"""
        try:
            msg = MIMEMultipart('alternative')
            msg['From'] = Config.SMTP_USERNAME
            msg['To'] = email
            msg['Subject'] = f"Your OTP for {purpose}"
            
            # Plain text version
            text_body = f"""
            Your OTP for {purpose} is: {otp_code}
            
            This OTP will expire in {Config.OTP_EXPIRE_MINUTES} minutes.
            
            If you didn't request this, please ignore this email.
            """
            
            # HTML version
            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                    <h2 style="color: #333;">OTP Verification</h2>
                    <p>Your OTP for <strong>{purpose}</strong> is:</p>
                    <div style="background-color: #f5f5f5; padding: 20px; text-align: center; border-radius: 5px; margin: 20px 0;">
                        <h1 style="color: #0066cc; font-size: 48px; margin: 0; letter-spacing: 5px;">{otp_code}</h1>
                    </div>
                    <p style="color: #666;">This OTP will expire in <strong>{Config.OTP_EXPIRE_MINUTES} minutes</strong>.</p>
                    <p style="color: #999; font-size: 12px; margin-top: 20px;">If you didn't request this OTP, please ignore this email.</p>
                </div>
            </body>
            </html>
            """
            
            # Attach both versions
            part1 = MIMEText(text_body, 'plain')
            part2 = MIMEText(html_body, 'html')
            msg.attach(part1)
            msg.attach(part2)
            
            # Send email
            server = smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT)
            server.starttls()
            server.login(Config.SMTP_USERNAME, Config.SMTP_PASSWORD)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"OTP email sent to {email}")
            return True
            
        except Exception as e:
            logger.error(f"Email send error: {e}")
            return False
    
    @staticmethod
    def store_otp(email, otp_code, purpose):
        """Store OTP in database"""
        expires_at = datetime.now() + timedelta(minutes=Config.OTP_EXPIRE_MINUTES)
        query = """
            INSERT INTO otp_codes (email, otp_code, purpose, expires_at)
            VALUES (:1, :2, :3, :4)
        """
        db.execute_query(query, (email, otp_code, purpose, expires_at))
        logger.info(f"OTP stored for {email} with purpose {purpose}")
    
    @staticmethod
    def verify_otp(email, otp_code, purpose):
        """Verify OTP and mark as used if valid"""
        query = """
            SELECT id, expires_at, is_used 
            FROM otp_codes 
            WHERE email = :1 
            AND otp_code = :2 
            AND purpose = :3 
            AND is_used = 'N'
            ORDER BY created_at DESC
            FETCH FIRST 1 ROW ONLY
        """
        result = db.fetch_one(query, (email, otp_code, purpose))
        
        if not result:
            return False, "Invalid OTP"
        
        otp_id, expires_at, is_used = result
        
        # Check if expired
        if datetime.now() > expires_at:
            return False, "OTP has expired"
        
        # Mark OTP as used
        update_query = "UPDATE otp_codes SET is_used = 'Y' WHERE id = :1"
        db.execute_query(update_query, (otp_id,))
        
        return True, "OTP verified successfully"
    
    @staticmethod
    def invalidate_old_otps(email, purpose):
        """Invalidate all unused OTPs for a user"""
        query = """
            UPDATE otp_codes 
            SET is_used = 'Y' 
            WHERE email = :1 AND purpose = :2 AND is_used = 'N'
        """
        db.execute_query(query, (email, purpose))
        logger.info(f"Invalidated old OTPs for {email} with purpose {purpose}")