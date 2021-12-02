try:
    from client import get, post, put, delete, head, patch, Auth
except:
    from .client import get, post, put, delete, head, patch, Auth

__all__ = ['get', 'post', 'put', 'delete', 'head', 'patch', 'Auth']
