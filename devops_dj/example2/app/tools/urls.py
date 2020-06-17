from django.urls import path
from tools import views

app_name = 'tools'


urlpatterns = [
    path(
        'report/upload/',
        views.ReportUploadView.as_view(),
        name='report_upload'
        ),
    path(
        'industry_add/',
        views.IndustryAddGetView.as_view(),
        name='industry'
        ),
    path(
        'region_add/',
        views.RegionAddGetView.as_view(),
        name='regions'
        ),
    path(
        'domain_status_check/',
        views.DomainStatusCheckView.as_view(),
        name='domain_check'
        ),
    path(
        'dmarc_detail_report/',
        views.DmarcReportScoreView.as_view(),
        name='dmarc_detail_report'
        ),
    path(
        'dmarc/threat/summary/',
        views.DmarcThreatsReportScore.as_view(),
        name='dmarc_threats_score'
        ),
    path(
        'dmarc/auth/summary/',
        views.DmarcAuthsummaryScoreView.as_view(),
        name='dmarc_threats_score'
        ),

]
