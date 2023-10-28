from scan.models import CveData, RouterCVE


def find_cve(device_name: str):

    brand = device_name.split(' ')[0]
    _sql = f"""
        select id, cve_id, description, vendor, product
        from cve_data
        where vendor like '%%{brand}%%' and MATCH(description) against("{device_name}" in NATURAL LANGUAGE MODE) limit 5;
    """
    data = [{
        'id': row.id,
        'cve_id': row.cve_id,
        'description': row.description,
        'vendor': row.vendor,
        'product': row.product
    } for row in CveData.objects.raw(_sql)]
    if data:
        return data
    return [{
        'id': row.id,
        'cve_id': row.cve_id,
        'description': row.description,
        'vendor': row.vendor,
        'product': row.product
    } for row in CveData.objects.raw(f"""
            select id, cve_id, description, vendor, product
            from cve_data
            where MATCH(description) against("{device_name}" in NATURAL LANGUAGE MODE) limit 5;
        """)]
