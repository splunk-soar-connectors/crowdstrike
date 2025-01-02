try:
    from client import Auth, delete, get, head, patch, post, put
except:
    from .client import Auth, delete, get, head, patch, post, put

__all__ = ['get', 'post', 'put', 'delete', 'head', 'patch', 'Auth']
