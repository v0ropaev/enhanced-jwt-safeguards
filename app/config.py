from dotenv import load_dotenv
import os

load_dotenv()

ALGORITHM = "RS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))
REFRESH_TOKEN_EXPIRE_MINUTES = int(os.getenv("REFRESH_TOKEN_EXPIRE_MINUTES", 60 * 24))

with open(os.getenv("PRIVATE_KEY_PATH", "private.pem"), "r") as f:
    PRIVATE_KEY = f.read()
with open(os.getenv("PUBLIC_KEY_PATH", "public.pem"), "r") as f:
    PUBLIC_KEY = f.read()
