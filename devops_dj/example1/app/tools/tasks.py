from celery import shared_task
from celery.utils.log import get_task_logger
from core import models
import dns.resolver


logger = get_task_logger(__name__)


@shared_task
def hello():
    print("Hello there!")
    logger.info("HELLO!  ")
    return 'HELLO ?'


@shared_task
def domain_check():
    all_data = models.Tenant.objects.filter(is_deleted=False)
    active_domain_list = []
    inactive_domain_list = []
    try:
        for data in all_data:
            print("data", data)
            cmd = "_dmarc."+data.domain
            try:
                domain_status = dns.resolver.query(cmd, 'TXT')

                if domain_status:
                    active_domain_list.append(data.domain)
                    all_data.filter(
                        domain=data.domain
                        ).update(is_active=True)
            except Exception:
                inactive_domain_list.append(data.domain)
                all_data.filter(
                    domain=data.domain
                    ).update(is_active=False)

        print("ACTIVE DOMAINS:", active_domain_list)

        print("INACTIVE DOMAINS:", inactive_domain_list)
        return True

    except Exception as e:
        raise e
