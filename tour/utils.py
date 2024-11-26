import jwt
from rest_framework_simplejwt.settings import api_settings

def decode_jwt_token(token):
    try:
        # Decode the token
        decoded_data = jwt.decode(
            token,
            api_settings.JWT_SECRET_KEY,
            algorithms=[api_settings.JWT_ALGORITHM]
        )
        return decoded_data
    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired'}
    except jwt.DecodeError:
        return {'error': 'Error decoding token'}
    except jwt.InvalidTokenError:
        return {'error': 'Invalid token'}
