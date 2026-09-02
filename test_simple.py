import oracledb
import re
import os
from dotenv import load_dotenv

load_dotenv()

def test_connection():
    database_url = os.getenv("DATABASE_URL")
    
    if not database_url:
        print("❌ DATABASE_URL not found in .env")
        return False
    
    print(f"Testing connection to: {database_url[:30]}...")
    
    # Remove oracle:// prefix
    url = database_url.replace('oracle://', '')
    
    # Parse URL
    pattern = r'^([^:]+):([^@]+)@([^:]+):(\d+)/(.+)$'
    match = re.match(pattern, url)
    
    if not match:
        print("❌ Could not parse URL")
        return False
    
    username, password, host, port, service = match.groups()
    
    print(f"Username: {username}")
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"Service: {service}")
    
    try:
        # Connect using parameters (this works!)
        dsn = f"{host}:{port}/{service}"
        connection = oracledb.connect(
            user=username,
            password=password,
            dsn=dsn
        )
        
        cursor = connection.cursor()
        cursor.execute("SELECT 'Connection successful!' FROM DUAL")
        result = cursor.fetchone()
        cursor.close()
        connection.close()
        
        print(f"✅ SUCCESS! {result[0]}")
        return True
        
    except Exception as e:
        print(f"❌ Failed: {e}")
        return False

if __name__ == "__main__":
    test_connection()