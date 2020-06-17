from rest_framework import generics
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from knox.auth import TokenAuthentication
from core.models import ReportDumpUploadbkp, Industry, \
     Regions, Tenant, ReportFeedbackRecord, \
     ReportFeedbackRecordAuthResultsDkim, ReportFeedbackRecordAuthResultsSpf
from custom_decorator import response_modify_decorator_post, \
     response_modify_decorator_get_after_execution
from tools.serializers import ReportUploadViewSerializer, \
        IndustryAddGetViewSerializer, RegionAddGetViewSerializer, \
        DomainStatusCheckViewSerializer, DmarcReportScoreViewSerializer
from rest_framework.response import Response
import dns.resolver
from datetime import datetime, timedelta
from django.db.models import Sum


class ReportUploadView(generics.CreateAPIView):
    """Upload Xml report viewset"""
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    queryset = ReportDumpUploadbkp.objects.filter(is_deleted=False)
    serializer_class = ReportUploadViewSerializer
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    @response_modify_decorator_post
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class IndustryAddGetView(generics.ListCreateAPIView):
    """ Add Industry in viewset"""
    permission_classes = [AllowAny]
    queryset = Industry.objects.filter(is_deleted=False)
    serializer_class = IndustryAddGetViewSerializer
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    @response_modify_decorator_get_after_execution
    def get(self, request, *args, **kwargs):
        response = super(self.__class__, self).get(request, *args, **kwargs)
        data_list = []
        for data in response.data:
            data_dict = {}
            data_dict['id'] = data['id']
            data_dict['name'] = data['name']
            data_list.append(data_dict)
        return Response(data_list)

    @response_modify_decorator_post
    def post(self, request, *args, **kwargs):
        return super(self.__class__, self).post(request, *args, **kwargs)


class RegionAddGetView(generics.ListCreateAPIView):
    """ Add regions in viewset"""
    permission_classes = [AllowAny]
    queryset = Regions.objects.filter(is_deleted=False)
    serializer_class = RegionAddGetViewSerializer
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    @response_modify_decorator_get_after_execution
    def get(self, request, *args, **kwargs):
        response = super(self.__class__, self).get(request, *args, **kwargs)
        data_list = []
        for data in response.data:
            data_dict = {}
            data_dict['id'] = data['id']
            data_dict['name'] = data['name']
            data_list.append(data_dict)
        return Response(data_list)

    @response_modify_decorator_post
    def post(self, request, *args, **kwargs):
        return super(self.__class__, self).post(request, *args, **kwargs)


class DomainStatusCheckView(generics.ListAPIView):
    """ domain status check in viewset"""
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    queryset = Tenant.objects.filter(is_deleted=False)
    serializer_class = DomainStatusCheckViewSerializer
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    def get_queryset(self):
        user = self.request.user
        return self.queryset.filter(user=user)

    @response_modify_decorator_get_after_execution
    def get(self, request, *args, **kwargs):
        response = super(self.__class__, self).get(request, *args, **kwargs)
        data_dict = {}
        active_domain_list = []
        inactive_domain_list = []

        for data in response.data:
            cmd = "_dmarc."+data['domain']
            try:
                domain_status = dns.resolver.query(cmd, 'TXT')

                if domain_status:
                    active_domain_list.append(data['domain'])
                    self.queryset.filter(
                        domain=data['domain']
                        ).update(is_active=True)
            except Exception:
                inactive_domain_list.append(data['domain'])
                self.queryset.filter(
                    domain=data['domain']
                    ).update(is_active=False)

        data_dict['active_domain'] = active_domain_list
        data_dict['inactive_domain'] = inactive_domain_list
        return Response(data_dict)


class DmarcReportScoreView(generics.ListAPIView):
    """  DmarcReportScore in viewset"""
    permission_classes = [IsAuthenticated]
    authentication_classes = [TokenAuthentication]
    queryset = ReportFeedbackRecord.objects.filter(is_deleted=False)
    serializer_class = DmarcReportScoreViewSerializer
    parser_classes = (MultiPartParser, FormParser, JSONParser)

    @response_modify_decorator_get_after_execution
    def get(self, request, *args, **kwargs):

        final_list = []
        user = self.request.user
        search_domain = self.request.query_params.get('search_domain', None)
        search_ip = self.request.query_params.get('search_ip', None)
        from_date = self.request.query_params.get('from_date', None)
        to_date = self.request.query_params.get('to_date', None)

        user = self.request.user
        active_domain = Tenant.objects.filter(
            is_active=True, user=user).values_list(
                'domain', flat=True).distinct()

        queryset = self.queryset.filter(
            meta_report__user=user,
            meta_report__domain__in=active_domain
            )

        filter = {}

        if from_date and to_date:
            start_object = datetime.strptime(from_date, '%Y-%m-%d').date()
            filter['meta_report__begin__date__gte'] = start_object
            end_object = datetime.strptime(to_date, '%Y-%m-%d').date()
            filter[
                'meta_report__begin__date__lte'
                ] = end_object + timedelta(days=1)
        if search_ip:
            search_ip_data = list(map(str, search_ip.split(",")))
            filter['source_ip__in'] = search_ip_data

        if search_domain:
            search_domain_data = list(map(str, search_domain.split(",")))
            filter['meta_report__domain__in'] = search_domain_data
        queryset = queryset.filter(**filter).order_by('-id')

        source_org_list = queryset.values_list(
            'meta_report__org_name', flat=True).distinct().order_by()
        final_list = []
        for source in source_org_list:
            source_dict = {}
            ip_data_list = []
            source_total_volume = 0
            source_dkim_pass_volume = 0
            source_spf_pass_volume = 0
            source_dict['source'] = source
            unique_ip = queryset.filter(
                meta_report__org_name=source
                ).values_list('source_ip', 'ip_name').distinct().order_by()

            for ip in unique_ip:
                ip_dict = {}
                ip_dict['ip'] = ip[0]
                ip_dict['reverse_dns'] = ip[1]
                report = queryset.filter(
                    meta_report__org_name=source,
                    source_ip=ip[0]
                    ).values(
                        'id',
                        'meta_report__domain',
                        'count',
                        'dkim',
                        'spf',
                        'header_from',
                        'disposition'
                        )
                report_data = []
                dkim_query = ReportFeedbackRecordAuthResultsDkim
                spf_query = ReportFeedbackRecordAuthResultsSpf
                for _report in report:
                    report_dict = {}
                    dkim_aligned = dkim_query.objects.filter(
                        record=_report['id'],
                        domain__iexact=_report['header_from'],
                        )
                    spf_aligned = spf_query.objects.filter(
                        record=_report['id'],
                        domain__iexact=_report['header_from'],
                        )
                    report_dict['id'] = _report['id']
                    report_dict['domain'] = _report['meta_report__domain']
                    report_dict['count'] = _report['count']
                    report_dict['dkim'] = _report['dkim']
                    report_dict['spf'] = _report['spf']
                    report_dict['header_from'] = _report['header_from']
                    report_dict['disposition'] = _report['disposition']

                    if dkim_aligned:
                        report_dict['dkim_verification'] = 'Aligned'
                    else:
                        report_dict['dkim_verification'] = 'Not Aligned'
                    if spf_aligned:
                        report_dict['spf_verification'] = 'Aligned'
                    else:
                        report_dict['spf_verification'] = 'Not Aligned'
                    report_data.append(report_dict)

                total_volume = report.aggregate(Sum('count'))['count__sum']
                dkim_volume_pass = report.filter(
                    dkim__iexact='pass'
                    ).aggregate(Sum('count'))['count__sum']
                if not dkim_volume_pass:
                    dkim_volume_pass = 0

                spf_volume_pass = report.filter(
                    spf__iexact='pass'
                    ).aggregate(Sum('count'))['count__sum']
                if not spf_volume_pass:
                    spf_volume_pass = 0

                source_total_volume += total_volume
                source_dkim_pass_volume += dkim_volume_pass
                source_spf_pass_volume += spf_volume_pass

                ip_dict['ip_report_details'] = report_data
                ip_dict['ip_total_volume'] = total_volume
                ip_dict['ip_dkim_pass_percentage'] = round(
                    (dkim_volume_pass/total_volume)*100, 2)
                ip_dict['ip_spf_pass_percentage'] = round(
                    (spf_volume_pass/total_volume)*100, 2)
                ip_data_list.append(ip_dict)
            source_dict['source_ip_data'] = ip_data_list
            source_dict['source_total_volume'] = source_total_volume
            source_dict['source_dkim_pass_percentage'] = round(
                    (source_dkim_pass_volume/source_total_volume)*100, 2)
            source_dict['source_spf_pass_percentage'] = round(
                    (source_spf_pass_volume/source_total_volume)*100, 2)
            final_list.append(source_dict)

        return Response(final_list)
