from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext as _
from core.models import Tenant, User, ReportDumpUploadbkp, \
        ReportFeedbackMetaData, ReportFeedbackRecord, \
        ReportFeedbackRecordAuthResultsDkim, RoleParentMenuAcessMappingTable, \
        ReportFeedbackRecordAuthResultsSpf, ChildMenu, \
        Industry, Regions, Profile, Role, ParentMenu, Domains, \
        RoleUserMappingTable, Access, MailTemplate, TenantUserMapping


admin.site.site_header = 'BrandSecure superAdmin Dashboard'


class UserAdmin(BaseUserAdmin):
    ordering = ['id']
    list_display = ['email', 'name']
    search_fields = ['email', 'name']
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('personal Info'), {'fields': ('name',)}),
        (
            _('permissions'),
            {'fields': ('is_active', 'is_staff', 'is_superuser')}
        ),
        (_('Important dates'), {'fields': ('last_login',)})
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2')
        }),
    )


admin.site.register(User, UserAdmin)


@admin.register(Tenant)
class Tenant(admin.ModelAdmin):
    list_display = [field.name for field in Tenant._meta.fields]


@admin.register(Domains)
class Domains(admin.ModelAdmin):
    list_display = [field.name for field in Domains._meta.fields]


@admin.register(TenantUserMapping)
class TenantUserMapping(admin.ModelAdmin):
    list_display = [field.name for field in TenantUserMapping._meta.fields]


@admin.register(ReportDumpUploadbkp)
class ReportDumpUploadbkp(admin.ModelAdmin):
    list_display = [field.name for field in ReportDumpUploadbkp._meta.fields]


@admin.register(ReportFeedbackMetaData)
class ReportFeedbackMetaData(admin.ModelAdmin):
    list_display = [
        field.name for field in ReportFeedbackMetaData._meta.fields
        ]


@admin.register(ReportFeedbackRecord)
class ReportFeedbackRecord(admin.ModelAdmin):
    list_display = [
        field.name for field in ReportFeedbackRecord._meta.fields
        ]


@admin.register(ReportFeedbackRecordAuthResultsDkim)
class ReportFeedbackRecordAuthResultsDkim(admin.ModelAdmin):
    list_display = [
        field.name for field in
        ReportFeedbackRecordAuthResultsDkim._meta.fields
        ]


@admin.register(ReportFeedbackRecordAuthResultsSpf)
class ReportFeedbackRecordAuthResultsSpf(admin.ModelAdmin):
    list_display = [
        field.name for field in ReportFeedbackRecordAuthResultsSpf._meta.fields
        ]


@admin.register(Industry)
class Industry(admin.ModelAdmin):
    list_display = [
        field.name for field in Industry._meta.fields
        ]


@admin.register(Regions)
class Regions(admin.ModelAdmin):
    list_display = [
        field.name for field in Regions._meta.fields
        ]


@admin.register(Profile)
class Profile(admin.ModelAdmin):
    list_display = [
        field.name for field in Profile._meta.fields
        ]


@admin.register(ParentMenu)
class ParentMenu(admin.ModelAdmin):
    list_display = [
        field.name for field in ParentMenu._meta.fields
        ]


@admin.register(ChildMenu)
class ChildMenu(admin.ModelAdmin):
    list_display = [
        field.name for field in ChildMenu._meta.fields
        ]


@admin.register(Role)
class Role(admin.ModelAdmin):
    list_display = [
        field.name for field in Role._meta.fields
        ]


@admin.register(RoleUserMappingTable)
class RoleUserMappingTable(admin.ModelAdmin):
    list_display = [
        field.name for field in RoleUserMappingTable._meta.fields
        ]


@admin.register(Access)
class Access(admin.ModelAdmin):
    list_display = [
        field.name for field in Access._meta.fields
        ]


@admin.register(RoleParentMenuAcessMappingTable)
class RoleParentMenuAcessMappingTable(admin.ModelAdmin):
    list_display = [
        field.name for field in RoleParentMenuAcessMappingTable._meta.fields
        ]


@admin.register(MailTemplate)
class MailTemplate(admin.ModelAdmin):
    list_display = [
        field.name for field in MailTemplate._meta.fields
        ]
