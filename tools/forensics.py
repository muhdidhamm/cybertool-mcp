"""Forensics, steganography & reverse engineering tools: binwalk, foremost, scalpel,
sleuthkit, yara, volatility3, steghide, stegosuite, outguess, exiftool, pdfcrack,
fcrackzip, bulk-extractor, radare2, rizin, gdb, strace, ltrace, apktool, etc."""

from tools.helpers import run_command, sanitize_arg
from tools.contracts import MemoryPipelineResult


def register_forensics_tools(mcp):

    # ── File Analysis ────────────────────────────────────────────────────

    @mcp.tool()
    async def binwalk_analyze(
        file_path: str,
        extract: bool = False,
        signature: bool = True,
        entropy: bool = False,
    ) -> dict:
        """Analyze a binary file for embedded files and executable code using Binwalk.

        Args:
            file_path: Path to the file to analyze.
            extract: Auto-extract discovered content. Default False.
            signature: Scan for file signatures. Default True.
            entropy: Show entropy analysis. Default False.
        """
        cmd = ["binwalk"]
        if extract:
            cmd.append("-e")
        if entropy:
            cmd.append("-E")
        cmd.append(sanitize_arg(file_path))
        return await run_command(cmd, timeout=120)

    @mcp.tool()
    async def foremost_recover(
        file_path: str,
        output_dir: str = "/opt/uts-mcp/output/foremost",
        file_types: str = "",
    ) -> dict:
        """Recover files from a disk image or binary using Foremost.

        Args:
            file_path: Path to input file or disk image.
            output_dir: Output directory for recovered files.
            file_types: Specific types to extract (e.g. "jpg,png,pdf"). Empty = all.
        """
        cmd = [
            "foremost", "-i", sanitize_arg(file_path),
            "-o", sanitize_arg(output_dir),
        ]
        if file_types:
            cmd.extend(["-t", sanitize_arg(file_types)])
        return await run_command(cmd, timeout=300)

    @mcp.tool()
    async def scalpel_carve(
        file_path: str,
        output_dir: str = "/opt/uts-mcp/output/scalpel",
        config: str = "/etc/scalpel/scalpel.conf",
    ) -> dict:
        """File carving/recovery using Scalpel (faster foremost alternative).

        Args:
            file_path: Path to disk image or file.
            output_dir: Output directory.
            config: Scalpel config file.
        """
        cmd = [
            "scalpel",
            "-c", sanitize_arg(config),
            "-o", sanitize_arg(output_dir),
            sanitize_arg(file_path),
        ]
        return await run_command(cmd, timeout=300)

    @mcp.tool()
    async def sleuthkit_fls(
        image_path: str,
        inode: str = "",
        recursive: bool = False,
    ) -> dict:
        """List files and directories in a disk image using fls (Sleuth Kit).

        Args:
            image_path: Path to disk image.
            inode: Specific inode to list. Empty = root.
            recursive: Recursive listing. Default False.
        """
        cmd = ["fls"]
        if recursive:
            cmd.append("-r")
        cmd.append(sanitize_arg(image_path))
        if inode:
            cmd.append(sanitize_arg(inode))
        return await run_command(cmd, timeout=60)

    @mcp.tool()
    async def sleuthkit_icat(
        image_path: str,
        inode: str,
        output_file: str = "/opt/uts-mcp/output/recovered_file",
    ) -> dict:
        """Extract a file from a disk image by inode using icat (Sleuth Kit).

        Args:
            image_path: Path to disk image.
            inode: Inode number to extract.
            output_file: Output file path.
        """
        cmd = ["icat", sanitize_arg(image_path), sanitize_arg(inode)]
        result = await run_command(cmd, timeout=60)
        if result.get("success") and result.get("stdout"):
            from tools.helpers import save_output
            save_output(output_file.split("/")[-1], result["stdout"])
        return result

    @mcp.tool()
    async def sleuthkit_mmls(image_path: str) -> dict:
        """Display partition layout of a disk image using mmls (Sleuth Kit).

        Args:
            image_path: Path to disk image.
        """
        cmd = ["mmls", sanitize_arg(image_path)]
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def sleuthkit_fsstat(image_path: str, offset: int = 0) -> dict:
        """Display filesystem details using fsstat (Sleuth Kit).

        Args:
            image_path: Path to disk image.
            offset: Partition offset in sectors. Default 0.
        """
        cmd = ["fsstat", "-o", str(int(offset)), sanitize_arg(image_path)]
        return await run_command(cmd, timeout=30)

    # ── Steganography ────────────────────────────────────────────────────

    @mcp.tool()
    async def steghide_extract(
        file_path: str,
        passphrase: str = "",
        output_file: str = "/opt/uts-mcp/output/steghide_extracted",
    ) -> dict:
        """Extract hidden data from image/audio files using Steghide.

        Args:
            file_path: Path to the stego file (JPEG, BMP, WAV, AU).
            passphrase: Passphrase for extraction. Empty = no passphrase.
            output_file: Output file for extracted data.
        """
        cmd = [
            "steghide", "extract",
            "-sf", sanitize_arg(file_path),
            "-xf", sanitize_arg(output_file),
            "-f",
        ]
        if passphrase:
            cmd.extend(["-p", sanitize_arg(passphrase)])
        else:
            cmd.extend(["-p", ""])
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def steghide_info(file_path: str) -> dict:
        """Display information about steganographic data in a file.

        Args:
            file_path: Path to the stego file.
        """
        cmd = ["steghide", "info", sanitize_arg(file_path), "-f"]
        return await run_command(cmd, timeout=15)

    @mcp.tool()
    async def outguess_extract(
        file_path: str,
        key: str = "",
        output_file: str = "/opt/uts-mcp/output/outguess_extracted",
    ) -> dict:
        """Extract steganographic data using OutGuess.

        Args:
            file_path: Path to stego image (JPEG, PNM, PPM).
            key: Extraction key/passphrase. Empty = no key.
            output_file: Output file.
        """
        cmd = ["outguess", "-r"]
        if key:
            cmd.extend(["-k", sanitize_arg(key)])
        cmd.extend([sanitize_arg(file_path), sanitize_arg(output_file)])
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def stegcracker_crack(
        file_path: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
    ) -> dict:
        """Brute-force steghide passphrases using StegCracker.

        Args:
            file_path: Path to stego file.
            wordlist: Wordlist path.
        """
        cmd = ["stegcracker", sanitize_arg(file_path), sanitize_arg(wordlist)]
        return await run_command(cmd, timeout=600)

    # ── Metadata & Strings ───────────────────────────────────────────────

    @mcp.tool()
    async def exiftool_extract(file_path: str) -> dict:
        """Extract metadata from files (images, documents, etc.) using ExifTool.

        Args:
            file_path: Path to the file.
        """
        cmd = ["exiftool", sanitize_arg(file_path)]
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def strings_extract(
        file_path: str,
        min_length: int = 4,
        encoding: str = "s",
    ) -> dict:
        """Extract printable strings from a binary file.

        Args:
            file_path: Path to the binary file.
            min_length: Minimum string length. Default 4.
            encoding: Encoding (s=7-bit, S=8-bit, l=16-bit LE, b=16-bit BE). Default s.
        """
        cmd = [
            "strings",
            "-n", str(int(min_length)),
            "-e", sanitize_arg(encoding),
            sanitize_arg(file_path),
        ]
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def file_identify(file_path: str) -> dict:
        """Identify a file's type using the 'file' command.

        Args:
            file_path: Path to the file.
        """
        cmd = ["file", sanitize_arg(file_path)]
        return await run_command(cmd, timeout=10)

    @mcp.tool()
    async def xxd_hexdump(
        file_path: str,
        length: int = 256,
        offset: int = 0,
    ) -> dict:
        """Display hex dump of a file.

        Args:
            file_path: Path to the file.
            length: Number of bytes to dump. Default 256.
            offset: Starting offset. Default 0.
        """
        cmd = [
            "xxd",
            "-l", str(int(length)),
            "-s", str(int(offset)),
            sanitize_arg(file_path),
        ]
        return await run_command(cmd, timeout=10)

    # ── Cracking Archives/PDFs ───────────────────────────────────────────

    @mcp.tool()
    async def pdfcrack_crack(
        pdf_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        timeout: int = 600,
    ) -> dict:
        """Crack password-protected PDF files using pdfcrack.

        Args:
            pdf_file: Path to the PDF file.
            wordlist: Wordlist path.
            timeout: Max seconds.
        """
        cmd = ["pdfcrack", "-f", sanitize_arg(pdf_file), "-w", sanitize_arg(wordlist)]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def fcrackzip_crack(
        zip_file: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        brute_force: bool = False,
        charset: str = "aA1",
        min_len: int = 1,
        max_len: int = 8,
        timeout: int = 600,
    ) -> dict:
        """Crack password-protected ZIP files using fcrackzip.

        Args:
            zip_file: Path to the ZIP file.
            wordlist: Wordlist path (for dictionary attack).
            brute_force: Use brute-force mode. Default False (dictionary mode).
            charset: Character set for brute-force (a=lowercase, A=uppercase, 1=digits).
            min_len: Min password length for brute-force.
            max_len: Max password length for brute-force.
            timeout: Max seconds.
        """
        cmd = ["fcrackzip", "-u"]
        if brute_force:
            cmd.extend([
                "-b", "-c", sanitize_arg(charset),
                "-l", f"{int(min_len)}-{int(max_len)}",
            ])
        else:
            cmd.extend(["-D", "-p", sanitize_arg(wordlist)])
        cmd.append(sanitize_arg(zip_file))
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def rarcrack_crack(
        rar_file: str,
        threads: int = 2,
        timeout: int = 600,
    ) -> dict:
        """Crack RAR, ZIP, or 7z archives using rarcrack.

        Args:
            rar_file: Path to the archive.
            threads: Number of threads. Default 2.
            timeout: Max seconds.
        """
        cmd = ["rarcrack", sanitize_arg(rar_file), "--threads", str(int(threads))]
        return await run_command(cmd, timeout=timeout)

    # ── Memory Forensics ─────────────────────────────────────────────────

    def _extract_iocs(text: str) -> list[dict]:
        rows: list[dict] = []
        for line in (text or "").splitlines():
            low = line.lower()
            if any(token in low for token in ["http://", "https://", ".onion", "powershell", "cmd.exe", "rundll32", "mimikatz", "wget ", "curl "]):
                rows.append({"type": "suspicious_indicator", "line": line.strip()[:500]})
        return rows[:200]

    @mcp.tool()
    async def volatility3_run(
        memory_dump: str,
        plugin: str = "windows.info",
        extra_args: str = "",
        timeout: int = 300,
    ) -> dict:
        """Analyze memory dumps using Volatility 3.

        Args:
            memory_dump: Path to memory dump file.
            plugin: Volatility3 plugin (e.g. windows.pslist, windows.netscan,
                    linux.bash, windows.hashdump, windows.filescan).
            extra_args: Additional arguments.
            timeout: Max seconds.
        """
        cmd = [
            "vol3", "-f", sanitize_arg(memory_dump),
            sanitize_arg(plugin),
        ]
        if extra_args:
            cmd.extend(sanitize_arg(extra_args).split())
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def volatility3_memory_pipeline(
        memory_dump: str,
        profile: str = "auto",
        timeout_per_plugin: int = 240,
    ) -> dict:
        """Run a chained Volatility3 memory pipeline and return normalized evidence.

        Pipeline includes:
        - OS/profile info
        - process list
        - network connections
        - command line history (if available)
        """
        dump = sanitize_arg(memory_dump).strip()
        if not dump:
            return {"success": False, "error": "memory_dump is required"}
        plugins = ["windows.info", "windows.pslist", "windows.netscan", "windows.cmdline"]
        outputs: dict[str, dict] = {}
        for plugin in plugins:
            outputs[plugin] = await run_command(["vol3", "-f", dump, plugin], timeout=timeout_per_plugin)
        iocs: list[dict] = []
        suspicious_proc: list[dict] = []
        suspicious_net: list[dict] = []
        timeline: list[dict] = []

        for plugin, result in outputs.items():
            stdout = str(result.get("stdout", ""))
            iocs.extend(_extract_iocs(stdout))
            if plugin.endswith("pslist"):
                for line in stdout.splitlines():
                    low = line.lower()
                    if any(token in low for token in ["powershell", "cmd.exe", "wscript", "cscript", "rundll32", "regsvr32"]):
                        suspicious_proc.append({"plugin": plugin, "line": line.strip()[:500]})
            if plugin.endswith("netscan"):
                for line in stdout.splitlines():
                    low = line.lower()
                    if any(token in low for token in [":4444", ":1337", "0.0.0.0", "established"]):
                        suspicious_net.append({"plugin": plugin, "line": line.strip()[:500]})
            timeline.append(
                {
                    "plugin": plugin,
                    "success": bool(result.get("success", False)),
                    "return_code": result.get("return_code"),
                }
            )

        model = MemoryPipelineResult(
            image_path=dump,
            profile=profile,
            plugins=plugins,
            iocs=iocs[:500],
            suspicious_processes=suspicious_proc[:200],
            suspicious_network=suspicious_net[:200],
            timeline=timeline,
            confidence_notes=[
                "Heuristic IOC extraction based on plugin output text.",
                "Correlate with disk, EDR, and cloud telemetry before final attribution.",
            ],
        )
        return {"success": True, "pipeline": model.model_dump(), "raw": outputs}

    @mcp.tool()
    async def yara_scan(
        rules_file: str,
        target_path: str,
        recursive: bool = False,
        timeout: int = 120,
    ) -> dict:
        """Scan files for malware signatures using YARA rules.

        Args:
            rules_file: Path to YARA rules file.
            target_path: File or directory to scan.
            recursive: Recurse into directories. Default False.
            timeout: Max seconds.
        """
        cmd = ["yara"]
        if recursive:
            cmd.append("-r")
        cmd.extend([sanitize_arg(rules_file), sanitize_arg(target_path)])
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def bulk_extractor_run(
        input_file: str,
        output_dir: str = "/opt/uts-mcp/output/bulk_extractor",
        timeout: int = 600,
    ) -> dict:
        """Extract useful information (emails, URLs, credit cards, etc.) from disk images using bulk_extractor.

        Args:
            input_file: Input file or disk image.
            output_dir: Output directory.
            timeout: Max seconds.
        """
        cmd = [
            "bulk_extractor",
            "-o", sanitize_arg(output_dir),
            sanitize_arg(input_file),
        ]
        return await run_command(cmd, timeout=timeout)

    # ── Reverse Engineering ──────────────────────────────────────────────

    @mcp.tool()
    async def radare2_analyze(
        file_path: str,
        commands: str = "aaa;afl;pdf@main;iS;ii",
    ) -> dict:
        """Analyze a binary with Radare2 (non-interactive mode).

        Args:
            file_path: Path to the binary file.
            commands: Semicolon-separated r2 commands. Default: full analysis + function list.
        """
        cmd_parts = sanitize_arg(commands).split(";")
        r2_script = "\n".join(cmd_parts)
        cmd = ["r2", "-q", "-c", r2_script, sanitize_arg(file_path)]
        return await run_command(cmd, timeout=120)

    @mcp.tool()
    async def rizin_analyze(
        file_path: str,
        commands: str = "aaa;afl;pdf@main;iS;ii",
    ) -> dict:
        """Analyze a binary with Rizin (Radare2 fork, non-interactive mode).

        Args:
            file_path: Path to the binary file.
            commands: Semicolon-separated rizin commands.
        """
        cmd_parts = sanitize_arg(commands).split(";")
        rz_script = "\n".join(cmd_parts)
        cmd = ["rizin", "-q", "-c", rz_script, sanitize_arg(file_path)]
        return await run_command(cmd, timeout=120)

    @mcp.tool()
    async def gdb_analyze(
        file_path: str,
        commands: str = "info functions\ninfo files\nquit",
    ) -> dict:
        """Run GDB commands non-interactively against a binary.

        Args:
            file_path: Path to the binary.
            commands: Newline-separated GDB commands.
        """
        cmd = ["gdb", "-batch"]
        for c in commands.split("\n"):
            c = c.strip()
            if c:
                cmd.extend(["-ex", sanitize_arg(c)])
        cmd.append(sanitize_arg(file_path))
        return await run_command(cmd, timeout=60)

    @mcp.tool()
    async def objdump_disassemble(
        file_path: str,
        section: str = "",
        intel_syntax: bool = True,
    ) -> dict:
        """Disassemble a binary using objdump.

        Args:
            file_path: Path to the binary.
            section: Specific section (e.g. ".text"). Empty = all.
            intel_syntax: Use Intel syntax. Default True.
        """
        cmd = ["objdump", "-d"]
        if intel_syntax:
            cmd.extend(["-M", "intel"])
        if section:
            cmd.extend(["-j", sanitize_arg(section)])
        cmd.append(sanitize_arg(file_path))
        return await run_command(cmd, timeout=60)

    @mcp.tool()
    async def strace_trace(
        command: str,
        timeout: int = 30,
    ) -> dict:
        """Trace system calls of a command using strace.

        Args:
            command: Command to trace.
            timeout: Max seconds.
        """
        cmd = ["strace", "-f"] + sanitize_arg(command).split()
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def ltrace_trace(
        command: str,
        timeout: int = 30,
    ) -> dict:
        """Trace library calls of a command using ltrace.

        Args:
            command: Command to trace.
            timeout: Max seconds.
        """
        cmd = ["ltrace", "-f"] + sanitize_arg(command).split()
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def apktool_decode(
        apk_path: str,
        output_dir: str = "/opt/uts-mcp/output/apktool_out",
    ) -> dict:
        """Decode an Android APK file using apktool.

        Args:
            apk_path: Path to the APK file.
            output_dir: Output directory for decoded resources.
        """
        cmd = ["apktool", "d", sanitize_arg(apk_path), "-o", sanitize_arg(output_dir), "-f"]
        return await run_command(cmd, timeout=120)

    @mcp.tool()
    async def dex2jar_convert(
        apk_path: str,
        output_file: str = "/opt/uts-mcp/output/classes.jar",
    ) -> dict:
        """Convert Android DEX to JAR for decompilation using dex2jar.

        Args:
            apk_path: Path to APK or DEX file.
            output_file: Output JAR path.
        """
        cmd = ["d2j-dex2jar", sanitize_arg(apk_path), "-o", sanitize_arg(output_file)]
        return await run_command(cmd, timeout=60)

    @mcp.tool()
    async def upx_unpack(
        file_path: str,
        output_file: str = "",
    ) -> dict:
        """Unpack UPX-compressed binaries.

        Args:
            file_path: Path to packed binary.
            output_file: Output path. Empty = unpack in-place.
        """
        cmd = ["upx", "-d"]
        if output_file:
            cmd.extend(["-o", sanitize_arg(output_file)])
        cmd.append(sanitize_arg(file_path))
        return await run_command(cmd, timeout=30)

    @mcp.tool()
    async def ddrescue_image(
        source: str,
        output_file: str,
        log_file: str = "",
        timeout: int = 600,
    ) -> dict:
        """Create a forensic disk image using ddrescue (error-tolerant copy).

        Args:
            source: Source device or file (e.g. /dev/sdb).
            output_file: Output image file path.
            log_file: Recovery log file path. Empty = auto.
            timeout: Max seconds.
        """
        cmd = ["ddrescue", "-f", sanitize_arg(source), sanitize_arg(output_file)]
        if log_file:
            cmd.append(sanitize_arg(log_file))
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def dc3dd_image(
        source: str,
        output_file: str,
        hash_type: str = "sha256",
        timeout: int = 600,
    ) -> dict:
        """Forensic disk imaging with built-in hashing using dc3dd.

        Args:
            source: Source device or file.
            output_file: Output image file path.
            hash_type: Hash algorithm (md5, sha1, sha256, sha512). Default sha256.
            timeout: Max seconds.
        """
        cmd = [
            "dc3dd",
            f"if={sanitize_arg(source)}",
            f"of={sanitize_arg(output_file)}",
            f"hash={sanitize_arg(hash_type)}",
            "log=/opt/uts-mcp/output/dc3dd_log.txt",
        ]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def jadx_decompile(
        apk_path: str,
        output_dir: str = "/opt/uts-mcp/output/jadx_output",
        timeout: int = 120,
    ) -> dict:
        """Decompile Android APK/DEX to Java source code using JADX.

        Args:
            apk_path: Path to APK or DEX file.
            output_dir: Output directory for decompiled source.
            timeout: Max seconds.
        """
        cmd = ["jadx", "-d", sanitize_arg(output_dir), sanitize_arg(apk_path)]
        return await run_command(cmd, timeout=timeout)

    @mcp.tool()
    async def samdump2_extract(
        sam_file: str,
        system_file: str,
        timeout: int = 30,
    ) -> dict:
        """Extract Windows password hashes from SAM and SYSTEM registry hive files.

        Args:
            sam_file: Path to SAM hive file.
            system_file: Path to SYSTEM hive file.
            timeout: Max seconds.
        """
        cmd = ["samdump2", sanitize_arg(system_file), sanitize_arg(sam_file)]
        return await run_command(cmd, timeout=timeout)
