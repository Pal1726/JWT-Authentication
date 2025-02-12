from rest_framework.permissions import BasePermission

class IsAdmin(BasePermission):
    """Allow only Admin users"""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'

class IsUser(BasePermission):
    """Allow only Normal Users"""
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'user'
