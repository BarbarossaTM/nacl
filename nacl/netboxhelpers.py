#!/usr/bin/python3
#
# Maximilian Wilhelm <max@sdn.clinic>
#  -- Thu, 15 Feb 2024 22:01:59 +0100
#

PREFIX_ITEMS_LITERAL = [
    "prefix",
    "is_pool",
    "description",
]
PREFIX_ITEMS = {
    "family" : "value",
    "status" : "value",
    "vrf" : "name",
    "role" : "slug",
}


def get_tag_slugs (obj: dict) -> list[str]:
    """
    Get the slugs from all tags in the given list.
    """
    slugs = []

    for tag in obj.get("tags", []):
        slugs.append (tag['slug'])

    return slugs


def strip_prefix (nb_prefix: dict) -> dict:
    """
    Strip down a Netbox Prefix to the attributes we care about.
    """
    pfx = {
        "tags" : get_tag_slugs(nb_prefix),
    }

    for item in PREFIX_ITEMS_LITERAL:
        pfx[item] = nb_prefix[item]

    for item, key in PREFIX_ITEMS.items():
        if nb_prefix[item] is not None:
            pfx[item] = nb_prefix[item][key]

    for key, val in nb_prefix.get("custom_fields", {}).items():
        if val is not None:
            pfx[key] = val

    return pfx
