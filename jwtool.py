import argparse
import base64
import glob
import itertools
import json
import re
import secrets
import sys
import warnings
from pathlib import Path

import jwt
from jwt.warnings import InsecureKeyLengthWarning

# Config

warnings.filterwarnings("ignore", category=InsecureKeyLengthWarning)
SUPPORTED_ALGORITHMS = ("HS256", "HS384", "HS512")
SIGNATURE_LENGTHS = {"HS256": 32, "HS384": 48, "HS512": 64}


# Args

parser = argparse.ArgumentParser(
    description=(
        "Simplify your JSON Web Token testing with a lightweight utility "
        "for decoding, inspecting and modifying JWTs."
    )
)

operation = parser.add_mutually_exclusive_group(required=True)

operation.add_argument(
    "-d", "--decode",
    action="store_true",
    help="Decode and inspect JWT contents"
)

operation.add_argument(
    "-m", "--modify",
    action="store_true",
    help="Modify an existing JWT by changing header or payload fields"
)

parser.add_argument(
    "-t", "--token",
    action="append",
    help="JWT supplied directly as a command-line argument (repeatable)"
)

parser.add_argument("-T", "--token-file", action="append", help="File containing a JWT (repeatable)")

parser.add_argument("-s", "--secret", help="JWT signing secret")

parser.add_argument(
    "-a", "--algorithm",
    default="HS256",
    choices=SUPPORTED_ALGORITHMS,
    help="JWT signing algorithm"
)

parser.add_argument(
    "-f", "--field",
    action="append",
    metavar="PATH=VALUE",
    help="Set a JWT header or payload field (e.g. payload.identity=admin)"
)

parser.add_argument(
    "-F", "--field-list",
    action="append",
    metavar="PATH=FILE",
    help="Generate field variations using values from a wordlist"
)

parser.add_argument("-o", "--output", help="Save a single modified JWT to a file")

parser.add_argument(
    "--output-dir",
    default="output",
    help="Directory to save generated tokens when producing multiple variations"
)

parser.add_argument("--pretty", action="store_true", help="Pretty-print decoded JWT contents")

signature_options = parser.add_mutually_exclusive_group()

signature_options.add_argument(
    "--no-signature",
    action="store_true",
    help="Generate an unsigned JWT using the 'none' algorithm"
)

signature_options.add_argument(
    "--invalid-signature",
    action="store_true",
    help="Generate a JWT with an invalid signature for signature-validation testing"
)


# Input handling

def load_tokens(args):
    tokens = []
    tokens.extend(args.token or [])

    for pattern in args.token_file or []:
        files = sorted(glob.glob(pattern))

        if not files:
            raise FileNotFoundError(f"No files matched: {pattern}")

        for filename in files:
            path = Path(filename)

            if not path.is_file():
                continue

            token = path.read_text(encoding="utf-8").strip()

            if token:
                tokens.append(token)

    if not tokens:
        raise ValueError("At least one JWT must be supplied")

    if args.modify and len(tokens) != 1:
        raise ValueError("--modify accepts exactly one JWT")

    return tokens


# Decoding

def decode_token(token):
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={"verify_signature": False})
    signature = token.split(".")[2]

    return header, payload, signature


def display_token(header, payload, signature, pretty=False):
    indent = 4 if pretty else None

    print("\n[+] Header\n")
    print(json.dumps(header, indent=indent))

    print("\n[+] Payload\n")
    print(json.dumps(payload, indent=indent))

    print("\n[+] Signature\n")
    print(signature if signature else "<empty>")


# Field parsing and modification

def parse_value(value):
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def parse_field(field):
    if "=" not in field:
        raise ValueError(f"Invalid field format: {field}")

    path, value = field.split("=", 1)
    path = path.split(".")

    if len(path) < 2 or path[0] not in ("header", "payload"):
        raise ValueError(f"Invalid field path: {path}. Expected header.FIELD or payload.FIELD")

    if any(not part for part in path):
        raise ValueError(f"Invalid field path: {field}")

    if path == ["header", "alg"]:
        raise ValueError("Use --algorithm to specify header.alg")

    return path, parse_value(value)


def set_nested_value(data, path, value):
    current = data

    for key in path[:-1]:
        if key not in current:
            current[key] = {}

        if not isinstance(current[key], dict):
            raise ValueError(f"Cannot traverse '{key}': existing value is not an object")

        current = current[key]

    current[path[-1]] = value


def set_token_field(header, payload, path, value):
    if path[0] == "header":
        target = header
    else:
        target = payload

    value = json.loads(json.dumps(value))
    set_nested_value(target, path[1:], value)


def apply_fields(header, payload, fields):
    changes = []

    for field in fields or []:
        path, value = parse_field(field)
        set_token_field(header, payload, path, value)
        changes.append((path, value))

    return changes


# Wordlist handling

def load_wordlist(field):
    if "=" not in field:
        raise ValueError(f"Invalid wordlist format: {field}")

    path, filename = field.split("=", 1)
    path = path.split(".")

    if len(path) < 2 or path[0] not in ("header", "payload"):
        raise ValueError(f"Invalid field path: {field}")

    if any(not part for part in path):
        raise ValueError(f"Invalid field path: {field}")

    if path == ["header", "alg"]:
        raise ValueError("Use --algorithm to specify header.alg")

    wordlist_path = Path(filename)
    if not wordlist_path.is_file():
        raise FileNotFoundError(f"Wordlist not found: {filename}")

    with wordlist_path.open("r", encoding="utf-8") as file:
        values = []
        for line in file:
            line = line.strip()
            if line:
                values.append(parse_value(line))

    if not values:
        raise ValueError(f"Wordlist is empty: {filename}")

    return path, values


def generate_variations(header, payload, field_lists, fixed_changes):
    wordlists = []
    value_lists = []
    for field in field_lists:
        path, values = load_wordlist(field)
        wordlists.append((path, values))
        value_lists.append(values)

    combinations = itertools.product(*value_lists)

    for combination in combinations:
        variation_header = json.loads(json.dumps(header))
        variation_payload = json.loads(json.dumps(payload))

        changes = list(fixed_changes)

        for (path, _), value in zip(wordlists, combination):
            set_token_field(variation_header, variation_payload, path, value)
            changes.append((path, value))

        yield variation_header, variation_payload, changes


# JWT generation

def encode_segment(data):
    encoded = json.dumps(data, separators=(",", ":")).encode("utf-8")

    return base64.urlsafe_b64encode(encoded).rstrip(b"=").decode("ascii")


def generate_token(header, payload, args):
    header = json.loads(json.dumps(header))
    payload = json.loads(json.dumps(payload))

    if args.no_signature:
        header["alg"] = "none"

        return f"{encode_segment(header)}.{encode_segment(payload)}."

    header["alg"] = args.algorithm

    if args.invalid_signature:
        signing_input = f"{encode_segment(header)}.{encode_segment(payload)}"

        invalid_signature = base64.urlsafe_b64encode(
            secrets.token_bytes(SIGNATURE_LENGTHS[args.algorithm])
        ).rstrip(b"=").decode("ascii")

        return f"{signing_input}.{invalid_signature}"

    if not args.secret:
        raise ValueError(
            "A signing secret is required unless using "
            "--no-signature or --invalid-signature"
        )

    signing_header = header.copy()
    del signing_header["alg"]

    return jwt.encode(
        payload,
        args.secret,
        algorithm=args.algorithm,
        headers=signing_header
    )


# Output filename generation

def filename_component(path, value):
    field_name = path[-1]

    if isinstance(value, str):
        field_value = value
    else:
        field_value = json.dumps(value, separators=(",", ":"))

    component = f"{field_name}_{field_value}"
    component = re.sub(r"[^a-zA-Z0-9_-]+", "_", component)

    return component.strip("_").lower()


def generate_filename(changes):
    components = []
    for path, value in changes:
        components.append(filename_component(path, value))
    filename = "_".join(components)

    # Keep filenames within a reasonable length.
    return f"{filename[:180]}.jwt"


# Output handling

def save_token(token, args, changes=None, index=None):
    if index is not None:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        filename = generate_filename(changes or [])
        output_file = output_dir / filename

        suffix = index
        while True:
            try:
                with output_file.open("x", encoding="utf-8") as file:
                    file.write(token)
                break
            except FileExistsError:
                output_file = output_dir / f"{Path(filename).stem}_{suffix:04d}.jwt"
                suffix += 1

    elif args.output:
        output_file = Path(args.output)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(token, encoding="utf-8")

    else:
        print(token)
        return

    print(f"[+] Token saved to: {output_file}")


# Modification

def modify_token(token, args):
    header, payload, _ = decode_token(token)

    fixed_changes = apply_fields(header, payload, args.field)

    if not args.field_list:
        generated = generate_token(header, payload, args)
        save_token(generated, args)
        return

    if args.output:
        raise ValueError(
            "--output cannot be used with --field-list. "
            "Use --output-dir instead."
        )

    count = 0
    variations = generate_variations(header, payload, args.field_list, fixed_changes)

    for count, (variation_header, variation_payload, changes) in enumerate(variations, start=1):
        generated = generate_token(variation_header, variation_payload, args)
        save_token(generated, args, changes=changes, index=count)

    print(f"\n[+] Generated {count} token(s)")


# Main

def main():
    args = parser.parse_args()

    if args.decode and (
        args.field or args.field_list or args.secret
        or args.no_signature or args.invalid_signature
        or args.output or args.output_dir != "output"
    ):
        parser.error("Modification and generation options cannot be used with --decode")

    if args.modify and not (args.field or args.field_list):
        parser.error("--modify requires at least one -f or -F argument")

    if args.modify and len(args.token or []) + len(args.token_file or []) != 1:
        parser.error("--modify requires exactly one JWT input")

    try:
        tokens = load_tokens(args)

        if args.decode:
            for index, token in enumerate(tokens, start=1):
                if len(tokens) > 1:
                    print(f"\n{'=' * 60}")
                    print(f"JWT {index}")
                    print(f"{'=' * 60}")

                header, payload, signature = decode_token(token)

                display_token(header, payload, signature, pretty=args.pretty)

        elif args.modify:
            modify_token(tokens[0], args)

    except (ValueError, OSError, jwt.PyJWTError) as error:
        print(f"[!] Error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

