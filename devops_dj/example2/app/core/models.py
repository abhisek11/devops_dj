from django.db import models
from django.utils.translation import gettext as _
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager,\
                                        PermissionsMixin


class UserManager(BaseUserManager):

    def create_user(self, email, password=None, **extra_fields):
        """Creates and saves a new user"""
        if not email:
            raise ValueError('User must have an email address')
        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        """creates and save a new super User"""
        user = self.create_user(email, password)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    """custom user model that supports using email instead of username"""
    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'


class Industry(models.Model):
    name = models.CharField(
            max_length=255, blank=True, null=True)
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
            User, related_name='Industry_created_by',
            on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
            User, related_name='Industry_owned_by',
            on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
            User, related_name='Industry_updated_by',
            on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.name)

    class Meta:
        verbose_name_plural = _("Industry")


class Regions(models.Model):
    name = models.CharField(
            max_length=255, blank=True, null=True)
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
            User, related_name='Regions_created_by',
            on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
            User, related_name='Regions_owned_by',
            on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
            User, related_name='Regions_updated_by',
            on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.name)

    class Meta:
        verbose_name_plural = _("Regions")


class Profile(models.Model):
    user = models.OneToOneField(
            User, on_delete=models.CASCADE, blank=True, null=True)
    firstname = models.CharField(max_length=255, blank=True, null=True)
    lastname = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    profile_pic = models.ImageField(
                    upload_to="avatar",
                    default="avatar/None/default.png"
                    )
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
            User, related_name='profile_created_by',
            on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
            User, related_name='profile_owned_by',
            on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
            User, related_name='profile_updated_by',
            on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = _("profile")


class Tenant(models.Model):
    org_admin = models.ForeignKey(
            User, on_delete=models.CASCADE, blank=True, null=True)
    company_name = models.CharField(
            max_length=255, blank=True, null=True)
    industry = models.ForeignKey(
                Industry, on_delete=models.CASCADE, blank=True, null=True)
    regions = models.ForeignKey(
                Regions, on_delete=models.CASCADE, blank=True, null=True)
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
            User, related_name='Tenant_created_by',
            on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
            User, related_name='Tenant_owned_by',
            on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
            User, related_name='Tenant_updated_by',
            on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = _("Tenant")


class Domains(models.Model):
    tenant = models.ForeignKey(
            Tenant, on_delete=models.CASCADE, blank=True, null=True)
    domain = models.CharField(
            max_length=255, blank=True, null=True)
    is_active = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
            User, related_name='Domains_created_by',
            on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
            User, related_name='Domains_owned_by',
            on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
            User, related_name='Domains_updated_by',
            on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = _("Domains")


class TenantUserMapping(models.Model):
    tenant = models.ForeignKey(
            Tenant, on_delete=models.CASCADE, blank=True, null=True)
    user = models.ForeignKey(
            User, on_delete=models.CASCADE, blank=True, null=True)
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
            User, related_name='TenantUserMapping_created_by',
            on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
            User, related_name='TenantUserMapping_owned_by',
            on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
            User, related_name='TenantUserMapping_updated_by',
            on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = _("Tenant User Mapping")


class ParentMenu(models.Model):

    MENU_TYPE = (
        ('LEFT_DOCK', 'LEFT_DOCK'),
        ('RIGHT_DOCK', 'RIGHT_DOCK'),
    )

    name = models.CharField(max_length=500, blank=True, null=True)
    url = models.CharField(max_length=500, blank=True, null=True)
    icon = models.CharField(max_length=500, blank=True, null=True)
    menu_type = models.CharField(
        max_length=50,
        choices=MENU_TYPE,
        default='LEFT_DOCK'
        )
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        User, related_name='ParentMenu_created_by',
        on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
        User, related_name='ParentMenu_owned_by',
        on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
        User, related_name='ParentMenu_updated_by',
        on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.name)

    class Meta:
        verbose_name_plural = _("Parent Menu")


class ChildMenu(models.Model):
    parent = models.ForeignKey(
        ParentMenu, blank=True, null=True,
        on_delete=models.CASCADE, related_name='parent_menu')
    name = models.CharField(max_length=500, blank=True, null=True)
    url = models.CharField(max_length=500, blank=True, null=True)
    icon = models.CharField(max_length=500, blank=True, null=True)
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        User, related_name='ChildMenu_created_by',
        on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
        User, related_name='ChildMenu_owned_by',
        on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
        User, related_name='ChildMenu_updated_by',
        on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.name)

    class Meta:
        verbose_name_plural = _("Child Menu")


class Role(models.Model):
    name = models.CharField(max_length=255, blank=True, null=True)
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        User, related_name='role_created_by',
        on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
        User, related_name='role_owned_by',
        on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
        User, related_name='role_updated_by',
        on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.name)

    class Meta:
        verbose_name_plural = _("Role")


class Access(models.Model):
    name = models.CharField(max_length=255, blank=True, null=True)
    is_create = models.BooleanField(default=False)
    is_read = models.BooleanField(default=False)
    is_delete = models.BooleanField(default=False)
    is_edit = models.BooleanField(default=False)
    is_execute = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        User, related_name='access_created_by',
        on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
        User, related_name='access_owned_by',
        on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
        User, related_name='access_updated_by',
        on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.name)

    class Meta:
        verbose_name_plural = _("Access")


class RoleParentMenuAcessMappingTable(models.Model):
    role = models.ForeignKey(
        Role, on_delete=models.CASCADE, blank=True, null=True)
    parent_menu = models.ForeignKey(
        ParentMenu, on_delete=models.CASCADE, blank=True, null=True)
    access = models.ForeignKey(
        Access, on_delete=models.CASCADE, blank=True, null=True)
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        User, related_name='role_menu_access_mapping_created_by',
        on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
        User, related_name='role_menu_access_mapping_owned_by',
        on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
        User, related_name='role_menu_access_mapping_updated_by',
        on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = _("Role Parent Menu Access mapping table")


class RoleUserMappingTable(models.Model):
    role = models.ForeignKey(
        Role, on_delete=models.CASCADE, blank=True, null=True)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, blank=True, null=True)
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        User, related_name='role_user_mapping_created_by',
        on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
        User, related_name='role_user_mapping_owned_by',
        on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
        User, related_name='role_user_mapping_updated_by',
        on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = _("Role user mapping table")


class ReportDumpUploadbkp(models.Model):
    user = models.ForeignKey(
            User, on_delete=models.CASCADE, blank=True, null=True)
    file_name = models.CharField(
        max_length=255, blank=True, null=True)
    data = models.TextField(blank=True, null=True)
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
            User, related_name='rdlb_created_by',
            on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
            User, related_name='rdlb_owned_by',
            on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
            User, related_name='rdlb_updated_by',
            on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = _("Report Dump Upload bkp")


class ReportFeedbackMetaData(models.Model):
    user = models.ForeignKey(
            User, on_delete=models.CASCADE, blank=True, null=True)
    org_name = models.CharField(
        max_length=255, blank=True, null=True)
    email = models.CharField(
        max_length=255, blank=True, null=True)
    extra_contact_info = models.CharField(
        max_length=255, blank=True, null=True)
    report_id = models.CharField(
        max_length=255, blank=True, null=True)
    begin = models.DateTimeField(
            blank=True, null=True)
    end = models.DateTimeField(
            blank=True, null=True)
    domain = models.CharField(
        max_length=255, blank=True, null=True)
    adkim = models.CharField(
        max_length=255, blank=True, null=True)
    aspf = models.CharField(
        max_length=255, blank=True, null=True)
    p = models.CharField(
        max_length=255, blank=True, null=True)
    sp = models.CharField(
        max_length=255, blank=True, null=True)
    pct = models.CharField(
        max_length=255, blank=True, null=True)
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
            User, related_name='rfmd_created_by',
            on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
            User, related_name='rfmd_owned_by',
            on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
            User, related_name='rfmd_updated_by',
            on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = _("Report Feedback MetaData")


class ReportFeedbackRecord(models.Model):
    meta_report = models.ForeignKey(
            ReportFeedbackMetaData,
            on_delete=models.CASCADE, blank=True, null=True)
    source_ip = models.CharField(
        max_length=255, blank=True, null=True)
    ip_name = models.CharField(
        max_length=255, blank=True, null=True)
    count = models.IntegerField(blank=True, null=True)
    disposition = models.CharField(
        max_length=255, blank=True, null=True)
    dkim = models.CharField(
        max_length=255, blank=True, null=True)
    spf = models.CharField(
        max_length=255, blank=True, null=True)
    header_from = models.CharField(
        max_length=255, blank=True, null=True)
    envelope_from = models.CharField(
        max_length=255, blank=True, null=True)
    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
            User, related_name='rfr_created_by',
            on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
            User, related_name='rfr_owned_by',
            on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
            User, related_name='rfr_updated_by',
            on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = _("Report Feedback Record")


class ReportFeedbackRecordAuthResultsDkim(models.Model):

    record = models.ForeignKey(
            ReportFeedbackRecord,
            on_delete=models.CASCADE, blank=True, null=True)

    domain = models.CharField(
        max_length=255, blank=True, null=True)
    selector = models.CharField(
        max_length=255, blank=True, null=True)
    result = models.CharField(
        max_length=255, blank=True, null=True)

    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
            User, related_name='rfrard_created_by',
            on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
            User, related_name='rfrard_owned_by',
            on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
            User, related_name='rfrard_updated_by',
            on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = _("Report Feedback Record Auth Results Dkim")


class ReportFeedbackRecordAuthResultsSpf(models.Model):

    record = models.ForeignKey(
            ReportFeedbackRecord,
            on_delete=models.CASCADE, blank=True, null=True)

    domain = models.CharField(
        max_length=255, blank=True, null=True)
    scope = models.CharField(
        max_length=255, blank=True, null=True)
    result = models.CharField(
        max_length=255, blank=True, null=True)

    is_deleted = models.BooleanField(default=False)
    created_by = models.ForeignKey(
            User, related_name='rfrars_created_by',
            on_delete=models.CASCADE, blank=True, null=True)
    owned_by = models.ForeignKey(
            User, related_name='rfrars_owned_by',
            on_delete=models.CASCADE, blank=True, null=True)
    updated_by = models.ForeignKey(
            User, related_name='rfrars_updated_by',
            on_delete=models.CASCADE, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return str(self.id)

    class Meta:
        verbose_name_plural = _("Report Feedback Record Auth Results Spf")


class MailTemplate(models.Model):
    name = models.CharField(max_length=255)
    code = models.CharField(max_length=255)
    subject = models.CharField(max_length=255)
    html_content = models.TextField()
    template_variable = models.TextField()

    class Meta:
        verbose_name_plural = _("Mail Template")

    def __str__(self):
        return self.name
