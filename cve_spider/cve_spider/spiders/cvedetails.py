import json
import scrapy

from urllib.parse import urljoin

from bs4 import BeautifulSoup

from ..items import CveSpiderItem


class CVEDetails(scrapy.Spider):
    name = "cve_detail"
    allowed_domains = ['cvedetails.com', 'cveapi.com']
    base_url = 'https://www.cvedetails.com/vulnerability-list/year-'
    baer_detail_url = "https://www.cvedetails.com/"

    # 初始页面入口：
    def start_requests(self):
        for year in range(2023, 1998, -1):
            url = self.base_url + str(year) + '/vulnerabilities.html'
            yield scrapy.Request(url, self.parse_list)

    # 分页入口：
    def parse_list(self, response):
        soup = BeautifulSoup(response.text, 'lxml')

        for page in soup.find('div', {'id': 'pagingb'}).find_all('a', href=True):
            _url = urljoin(response.url, page['href'])
            yield scrapy.Request(_url, self.parse_info)

    @staticmethod
    def parse_cve_json(response):
        _data = json.loads(response.text)
        cve = CveSpiderItem()
        cve['description'] = _data['cve'].get("description", {}).get('description_data')[0]['value']
        cve['cve_id'] = _data['cve']['CVE_data_meta']['ID']
        cve['cve_url'] = f'https://www.cvedetails.com/cve/{cve["cve_id"]}/'

        base_metric_v2 = _data['impact'].get('baseMetricV2')
        if base_metric_v2:
            cve['score'] = base_metric_v2['cvssV2']['baseScore']
            cve['access'] = base_metric_v2['cvssV2']['accessVector']
            cve['complexity'] = base_metric_v2['cvssV2']['accessComplexity']
            cve['authentication'] = base_metric_v2['cvssV2']['authentication']
            cve['confidentiality'] = base_metric_v2['cvssV2']['confidentialityImpact']
            cve['integrity'] = base_metric_v2['cvssV2']['integrityImpact']
            cve['availability'] = base_metric_v2['cvssV2']['availabilityImpact']
        else:
            base_metric_v3 = _data['impact'].get('baseMetricV3')
            if not base_metric_v3:
                return
            cve['score'] = base_metric_v3['cvssV3']['baseScore']
            cve['access'] = base_metric_v3['cvssV3'].get('accessVector')
            cve['complexity'] = base_metric_v3['cvssV3'].get('accessComplexity')
            cve['authentication'] = base_metric_v3['cvssV3'].get('authentication')
            cve['confidentiality'] = base_metric_v3['cvssV3']['confidentialityImpact']
            cve['integrity'] = base_metric_v3['cvssV3']['integrityImpact']
            cve['availability'] = base_metric_v3['cvssV3']['availabilityImpact']

        cve['vendor'] = ''
        cve['product'] = ''
        cve['version'] = ''
        vendor_data = _data['cve'].get('affects', {}).get('vendor', {}).get('vendor_data', [])
        if vendor_data:
            cve['vendor'] = vendor_data[0]['vendor_name']
            product_data = vendor_data[0]['product']['product_data']
            if product_data:
                cve['product'] = product_data[0]['product_name']
                version_data = product_data[0]['version']['version_data']
                if version_data:
                    cve['version'] = ','.join([f'{_["version_affected"]}{_["version_value"]}' for _ in version_data])
        yield cve

    # 分页处理：
    def parse_info(self, response):
        soup = BeautifulSoup(response.text, 'lxml')
        page_result = soup.find('div', {'id': 'searchresults'})
        for item in page_result.find_all('div'):
            _id = item.find('h3', {'data-tsvfield': 'cveId'})
            if _id:
                cve_id = _id.get_text(strip=True)
                yield scrapy.Request(f'https://v1.cveapi.com/{cve_id}.json', self.parse_cve_json)
