"""Cryptography & encoding tools: hash identification, encoding/decoding, hash generation."""

import hashlib
from tools.helpers import run_command, sanitize_arg


def register_crypto_tools(mcp):

    @mcp.tool()
    async def hash_identify(hash_value: str) -> dict:
        """Identify the type of a hash using hashid and hash-identifier.

        Args:
            hash_value: The hash string to identify.
        """
        result = await run_command(
            ["hashid", sanitize_arg(hash_value)], timeout=10
        )
        return result

    @mcp.tool()
    async def generate_hash(
        text: str,
        algorithm: str = "sha256",
    ) -> dict:
        """Generate a hash of the given text.

        Args:
            text: Text to hash.
            algorithm: Hash algorithm (md5, sha1, sha256, sha512, sha3_256). Default sha256.
        """
        algo = algorithm.lower().strip()
        try:
            h = hashlib.new(algo, text.encode("utf-8"))
            return {
                "success": True,
                "algorithm": algo,
                "input": text,
                "hash": h.hexdigest(),
            }
        except ValueError:
            return {"success": False, "error": f"Unknown algorithm: {algo}"}

    @mcp.tool()
    async def base64_encode(text: str) -> dict:
        """Base64 encode a string.

        Args:
            text: Text to encode.
        """
        import base64
        encoded = base64.b64encode(text.encode("utf-8")).decode("utf-8")
        return {"success": True, "input": text, "encoded": encoded}

    @mcp.tool()
    async def base64_decode(encoded: str) -> dict:
        """Base64 decode a string.

        Args:
            encoded: Base64 encoded string to decode.
        """
        import base64
        try:
            decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
            return {"success": True, "input": encoded, "decoded": decoded}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @mcp.tool()
    async def url_encode(text: str) -> dict:
        """URL encode a string.

        Args:
            text: Text to URL encode.
        """
        from urllib.parse import quote
        return {"success": True, "input": text, "encoded": quote(text)}

    @mcp.tool()
    async def url_decode(encoded: str) -> dict:
        """URL decode a string.

        Args:
            encoded: URL encoded string.
        """
        from urllib.parse import unquote
        return {"success": True, "input": encoded, "decoded": unquote(encoded)}

    @mcp.tool()
    async def hex_encode(text: str) -> dict:
        """Convert text to hexadecimal.

        Args:
            text: Text to convert.
        """
        return {
            "success": True,
            "input": text,
            "hex": text.encode("utf-8").hex(),
        }

    @mcp.tool()
    async def hex_decode(hex_string: str) -> dict:
        """Convert hexadecimal back to text.

        Args:
            hex_string: Hex string to decode.
        """
        try:
            decoded = bytes.fromhex(hex_string).decode("utf-8", errors="replace")
            return {"success": True, "input": hex_string, "decoded": decoded}
        except Exception as e:
            return {"success": False, "error": str(e)}
