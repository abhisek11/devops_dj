from django.db import transaction
from core.models import ReportFeedbackRecord, \
        ReportFeedbackMetaData, ReportDumpUploadbkp, \
        ReportFeedbackRecordAuthResultsDkim, \
        ReportFeedbackRecordAuthResultsSpf, Industry, Regions, Tenant
from rest_framework import serializers
from custom_exception_message import CustomAPIException
from rest_framework import status
from custom_functions import xml_to_json
import json
from datetime import datetime
from dns import reversename, resolver


class ReportUploadViewSerializer(serializers.ModelSerializer):
    """Serializer for the user report upload"""
    created_by = serializers.CharField(
        default=serializers.CurrentUserDefault())
    owned_by = serializers.CharField(
        default=serializers.CurrentUserDefault())
    report_file = serializers.FileField(required=False)
    file_data = serializers.DictField(required=False)

    class Meta:
        model = ReportDumpUploadbkp
        fields = (
            'report_file', 'file_data', 'created_by', 'owned_by',
            )

    def create(self, validated_data):

        user = self.context['request'].user
        created_by = validated_data.get('created_by')
        owned_by = validated_data.get('owned_by')
        upload_file = validated_data.get('report_file')
        file_name = upload_file.name
        file_exist = ReportDumpUploadbkp.objects.filter(
            file_name=file_name
            ).exists()
        file_data = xml_to_json(upload_file)
        file_json = json.loads(file_data)

        if file_exist:
            raise CustomAPIException(
                None,
                "Duplicate ! The file with same name is already in data base ",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        domain_list = Tenant.objects.filter(
                                            user=user
                                            ).values_list('domain', flat=True)
        to_check = file_json['feedback']['policy_published']['domain']
        if to_check not in domain_list:
            raise CustomAPIException(
                None,
                "sorry ! Report does not belong to any of registered domain" +
                " please add "+to_check+" to upload this report",
                status_code=status.HTTP_400_BAD_REQUEST
            )

        with transaction.atomic():

            ReportDumpUploadbkp.objects.create(
                user=user,
                data=file_json,
                file_name=file_name,
                created_by=created_by,
                owned_by=owned_by
                )

            meta_data_report = ReportFeedbackMetaData.objects.create(
                user=user,
                org_name=file_json['feedback']['report_metadata']['org_name'],
                email=file_json['feedback']['report_metadata']['email'],
                extra_contact_info=file_json['feedback'][
                                    'report_metadata'][
                                        'extra_contact_info'
                                        ] if 'extra_contact_info' in file_json[
                                            'feedback'][
                                    'report_metadata'] else None,
                report_id=file_json['feedback'][
                                    'report_metadata'][
                                        'report_id'],
                begin=datetime.fromtimestamp(int(
                    file_json['feedback'][
                                    'report_metadata'][
                                        'date_range']['begin'])),
                end=datetime.fromtimestamp(int(
                    file_json['feedback'][
                        'report_metadata'][
                            'date_range']['end']
                    )),
                domain=file_json['feedback'][
                                'policy_published']['domain'],
                adkim=file_json['feedback'][
                                'policy_published']['adkim'],
                aspf=file_json['feedback']['policy_published']['aspf'],
                p=file_json['feedback']['policy_published']['p'],
                sp=file_json['feedback']['policy_published']['sp'],
                pct=file_json['feedback']['policy_published']['pct'],
                created_by=created_by,
                owned_by=owned_by
            )
            records = file_json['feedback']['record']
            if isinstance(records, (list)):
                for record in records:
                    try:
                        rev_name = reversename.from_address(
                            record['row']['source_ip'])
                        reversed_dns = str(resolver.query(rev_name, "PTR")[0])
                    except Exception:
                        reversed_dns = record['row']['source_ip']
                    records_created = ReportFeedbackRecord.objects.create(
                        meta_report=meta_data_report,
                        source_ip=record['row']['source_ip'],
                        ip_name=reversed_dns,
                        count=record['row']['count'],
                        disposition=record['row'][
                                    'policy_evaluated']['disposition'],
                        dkim=record['row'][
                                    'policy_evaluated']['dkim'],
                        spf=record['row'][
                                        'policy_evaluated']['spf'],
                        header_from=record[
                            'identifiers'][
                            'header_from'] if 'header_from'in record[
                                'identifiers'] else None,
                        envelope_from=record[
                            'identifiers'][
                            'envelope_from'] if 'envelope_from' in record[
                            'identifiers'] else None,
                    )
                    auth_dkim = record[
                        'auth_results']['dkim'] if 'dkim' in record[
                        'auth_results'] else None
                    auth_spf = record[
                        'auth_results']['spf'] if 'spf' in record[
                        'auth_results'] else None
                    if auth_dkim:
                        if isinstance(auth_dkim, (list)):
                            for au_dkim in auth_dkim:
                                ReportFeedbackRecordAuthResultsDkim.objects.\
                                 create(
                                    record=records_created,
                                    domain=au_dkim[
                                        'domain'
                                        ] if 'domain' in au_dkim else None,
                                    selector=au_dkim[
                                        'selector'
                                        ] if 'selector' in au_dkim else None,
                                    result=au_dkim[
                                        'result'
                                        ] if 'result' in au_dkim else None,
                                    created_by=created_by,
                                    owned_by=owned_by
                                    )
                        else:
                            ReportFeedbackRecordAuthResultsDkim.objects.create(
                                    record=records_created,
                                    domain=auth_dkim[
                                        'domain'
                                        ] if 'domain' in auth_dkim else None,
                                    selector=auth_dkim[
                                        'selector'
                                        ] if 'selector' in auth_dkim else None,
                                    result=auth_dkim[
                                        'result'
                                        ]if 'result' in auth_dkim else None,
                                    created_by=created_by,
                                    owned_by=owned_by
                                )
                    if auth_spf:
                        if isinstance(auth_spf, (list)):
                            for au_spf in auth_spf:
                                ReportFeedbackRecordAuthResultsSpf.objects.\
                                 create(
                                    record=records_created,
                                    domain=au_spf[
                                        'domain'
                                        ] if 'domain' in au_spf else None,
                                    scope=au_spf[
                                        'scope'
                                        ] if 'scope' in au_spf else None,
                                    result=au_spf[
                                        'result'
                                        ] if 'result' in au_spf else None,
                                    created_by=created_by,
                                    owned_by=owned_by

                                    )
                        else:
                            ReportFeedbackRecordAuthResultsSpf.objects.create(
                                    record=records_created,
                                    domain=auth_spf[
                                        'domain'
                                        ] if 'domain' in auth_spf else None,
                                    scope=auth_spf[
                                        'scope'
                                        ] if 'scope' in auth_spf else None,
                                    result=auth_spf[
                                        'result'
                                        ] if 'result' in auth_spf else None,
                                    created_by=created_by,
                                    owned_by=owned_by
                                )
            else:
                try:
                    rev_name = reversename.from_address(
                        records['row']['source_ip'])
                    reversed_dns = str(resolver.query(rev_name, "PTR")[0])
                except Exception:
                    reversed_dns = records['row']['source_ip']
                records_created = ReportFeedbackRecord.objects.create(
                        meta_report=meta_data_report,
                        source_ip=records['row']['source_ip'],
                        ip_name=reversed_dns,
                        count=records['row']['count'],
                        disposition=records['row']['policy_evaluated'][
                                            'disposition'],
                        dkim=records['row']['policy_evaluated'][
                                            'dkim'],
                        spf=records['row']['policy_evaluated'][
                                            'spf'],
                        header_from=records['identifiers'][
                                            'header_from'
                                            ] if 'header_from' in records[
                                                'identifiers'] else None,
                        envelope_from=records[
                                        'identifiers'
                                        ][
                                            'envelope_from'
                                            ] if 'envelope_from' in records[
                                                'identifiers'
                                                ] else None,
                        )
                auth_dkim = records['auth_results'][
                                'dkim'
                                ] if 'dkim' in records[
                                    'auth_results'] else None
                auth_spf = records['auth_results'][
                                'spf'] if 'spf' in records[
                                    'auth_results'] else None
                if auth_dkim:
                    if isinstance(auth_dkim, (list)):
                        for au_dkim in auth_dkim:
                            ReportFeedbackRecordAuthResultsDkim.objects.create(
                                record=records_created,
                                domain=au_dkim[
                                        'domain'
                                        ] if 'domain' in au_dkim else None,
                                selector=au_dkim[
                                          'selector'
                                         ] if 'selector' in au_dkim else None,
                                result=au_dkim[
                                        'result'
                                        ] if 'result' in au_dkim else None,
                                created_by=created_by,
                                owned_by=owned_by
                            )
                    else:
                        ReportFeedbackRecordAuthResultsDkim.objects.create(
                                record=records_created,
                                domain=auth_dkim[
                                         'domain'
                                         ] if 'domain' in auth_dkim else None,
                                selector=auth_dkim[
                                          'selector'
                                        ] if 'selector' in auth_dkim else None,
                                result=auth_dkim[
                                        'result'
                                        ] if 'result' in auth_dkim else None,
                                created_by=created_by,
                                owned_by=owned_by
                            )
                if auth_spf:
                    if isinstance(auth_spf, (list)):
                        for au_spf in auth_spf:
                            ReportFeedbackRecordAuthResultsSpf.objects.create(
                                record=records_created,
                                domain=au_spf[
                                        'domain'
                                        ] if 'domain' in au_spf else None,
                                scope=au_spf[
                                        'scope'
                                        ] if 'scope' in au_spf else None,
                                result=au_spf[
                                        'result'
                                        ] if 'result' in au_spf else None,
                                created_by=created_by,
                                owned_by=owned_by

                            )
                    else:
                        ReportFeedbackRecordAuthResultsSpf.objects.create(
                                record=records_created,
                                domain=auth_spf[
                                        'domain'
                                        ] if 'domain' in auth_spf else None,
                                scope=auth_spf[
                                        'scope'
                                        ] if 'scope' in auth_spf else None,
                                result=auth_spf[
                                        'result'
                                        ] if 'result' in auth_spf else None,
                                created_by=created_by,
                                owned_by=owned_by
                            )

        validated_data.pop('report_file')
        validated_data['file_data'] = file_json
        return validated_data


class IndustryAddGetViewSerializer(serializers.ModelSerializer):
    names = serializers.ListField(required=False)

    class Meta:
        model = Industry
        fields = ('__all__')

    def create(self, validated_data):
        try:
            names = validated_data.get('names')
            with transaction.atomic():
                if not names:
                    raise CustomAPIException(
                        None,
                        "field is empty",
                        status_code=status.HTTP_400_BAD_REQUEST
                    )

                for name in names:
                    Industry.objects.create(
                        name=name
                        )

                return validated_data

        except Exception as e:
            raise e


class RegionAddGetViewSerializer(serializers.ModelSerializer):
    names = serializers.ListField(required=False)

    class Meta:
        model = Regions
        fields = ('__all__')

    def create(self, validated_data):
        try:
            names = validated_data.get('names')
            with transaction.atomic():
                if not names:
                    raise CustomAPIException(
                        None,
                        "field is empty",
                        status_code=status.HTTP_400_BAD_REQUEST
                    )
                for name in names:
                    Regions.objects.create(
                        name=name
                        )

                return validated_data

        except Exception as e:
            raise e


class DomainStatusCheckViewSerializer(serializers.ModelSerializer):

    class Meta:
        model = Tenant
        fields = ('__all__')


class DmarcReportScoreViewSerializer(serializers.ModelSerializer):

    class Meta:
        model = ReportFeedbackMetaData
        fields = ('__all__')
