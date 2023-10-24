import random
import string

BASE_CHARS = string.ascii_letters + string.digits


def get_task_id(length=32) -> str:
    return ''.join(random.choices(BASE_CHARS, k=length))
