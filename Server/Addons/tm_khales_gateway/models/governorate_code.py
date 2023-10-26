"""Governorate Code"""

GOVERNORATE_CODES = {
    'C': 1,
    'GZ': 2,
    'ALX': 3,
    'DK': 4,
    'BA': 5,
    'BH': 6,
    'FYM': 7,
    'GH': 8,
    'IS': 9,
    'MNF': 10,
    'MN': 11,
    'KB': 12,
    'WAD': 13,
    'SUZ': 14,
    'ASN': 15,
    'AST': 16,
    'BNS': 17,
    'PTS': 18,
    'DT': 19,
    'SHR': 20,
    'JS': 21,
    'KFS': 22,
    'MT': 23,
    'LX': 24,
    'KN': 25,
    'SIN': 26,
    'SHG': 27,
}


def get_governorate_code(code):
    """Get the governorate code.

    :param code: The code of the governorate.
    :type code: str
    """
    if not code:
        return 28
    return GOVERNORATE_CODES.get(code, 28)
