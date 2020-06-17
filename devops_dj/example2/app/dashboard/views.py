from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from knox.auth import TokenAuthentication
from core import models
from custom_decorator import response_modify_decorator_post, \
        response_modify_decorator_get_after_execution
from dashboard import serializers
from rest_framework.response import Response


class DashboardUserCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    queryset = models.User.objects.all()
    serializer_class = serializers.DashboardUserCreateViewSerializer
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    @response_modify_decorator_post
    def post(self, request, *args, **kwargs):
        return super(self.__class__, self).post(request, *args, **kwargs)


class DashboardDynamicMenuView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    queryset = models.RoleUserMappingTable.objects.all()
    serializer_class = serializers.DashboardDynamicMenuViewSerializer
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    @response_modify_decorator_get_after_execution
    def get(self, request, *args, **kwargs):
        user = self.request.user
        role = self.queryset.get(user=user).role
        menu_access = models.RoleParentMenuAcessMappingTable.objects.filter(
            role=role
        ).values(
            'parent_menu__id',
            'parent_menu__name',
            'parent_menu__url',
            'parent_menu__icon',
            'parent_menu__menu_type',
            'access__id',
            'access__name',
            'access__is_create',
            'access__is_read',
            'access__is_delete',
            'access__is_edit',
            'access__is_execute',
        )
        # print("menu_access", menu_access)
        parent_ids = menu_access.values_list('parent_menu__id', flat=True)
        children_menu = models.ChildMenu.objects.filter(
            parent__in=parent_ids
        )
        print("children_menu", children_menu)
        final_dict = {}
        left_dock = []
        right_dock = []
        for p_menu in menu_access:
            data_dict = {}
            if p_menu['parent_menu__menu_type'] == 'LEFT_DOCK':
                child_data = children_menu.filter(
                    parent=p_menu['parent_menu__id']
                ).values('name', 'url', 'icon')
                print("child_data", child_data)
                data_dict['child_menu'] = child_data
                data_dict['parent_menu__id'] = p_menu['parent_menu__id']
                data_dict['parent_menu__name'] = p_menu['parent_menu__name']
                data_dict['parent_menu__url'] = p_menu['parent_menu__url']
                data_dict['parent_menu__icon'] = p_menu['parent_menu__icon']
                data_dict['parent_menu__id'] = p_menu['parent_menu__id']
                data_dict['access'] = {
                    'id': p_menu['access__id'],
                    'name': p_menu['access__name'],
                    'is_create': p_menu['access__is_create'],
                    'is_read': p_menu['access__is_read'],
                    'is_delete': p_menu['access__is_delete'],
                    'is_edit': p_menu['access__is_edit'],
                    'is_execute': p_menu['access__is_execute'],
                }
                left_dock.append(data_dict)
            else:
                data_dict['parent_menu__id'] = p_menu['parent_menu__id']
                data_dict['parent_menu__name'] = p_menu['parent_menu__name']
                data_dict['parent_menu__url'] = p_menu['parent_menu__url']
                data_dict['parent_menu__icon'] = p_menu['parent_menu__icon']
                data_dict['parent_menu__id'] = p_menu['parent_menu__id']
                data_dict['access'] = {
                    'id': p_menu['access__id'],
                    'name': p_menu['access__name'],
                    'is_create': p_menu['access__is_create'],
                    'is_read': p_menu['access__is_read'],
                    'is_delete': p_menu['access__is_delete'],
                    'is_edit': p_menu['access__is_edit'],
                    'is_execute': p_menu['access__is_execute'],
                }
                right_dock.append(data_dict)
        final_dict['user'] = user.id
        final_dict['user_name'] = user.name
        final_dict['role'] = role.name
        final_dict['left_menu'] = left_dock
        final_dict['right_menu'] = right_dock
        return Response(final_dict)
