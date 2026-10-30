#!/usr/bin/env python3
"""Small synthetic negative controls; contains no private APK values."""
import compare_private_resource_evidence as compare


def reject(host, native, expected):
    try:
        compare.compare_stored_maps(host, native)
    except compare.CheckFailure as error:
        if str(error) == expected:
            return
        raise RuntimeError("unexpected negative-control terminal") from error
    raise RuntimeError("invalid resource comparison accepted")


def main():
    one = {"res/synthetic.xml":"a" * 64, "resources.arsc":"b" * 64}
    compare.compare_stored_maps(one, dict(one))
    reject(one, {"res/synthetic.xml":"a" * 64}, "STORED_RESOURCE_MAPS_DIFFER")
    reject(one, {"res/synthetic.xml":"c" * 64, "resources.arsc":"b" * 64}, "STORED_RESOURCE_MAPS_DIFFER")
    reject(one, {"res/synthetic.xml":"", "resources.arsc":"b" * 64}, "RESOURCE_MAP_VALUE_INVALID")
    print("3 synthetic negative controls rejected")


if __name__ == "__main__":
    main()
