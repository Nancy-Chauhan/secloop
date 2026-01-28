"""Ralph Loop - Core loop logic."""

import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Callable
from datetime import datetime

from .scanners import get_scanner, Scanner, Vulnerability
from . import ui


@dataclass
class LoopResult:
    """Result of a Ralph loop execution."""
    success: bool
    iterations: int
    initial_vulns: int
    final_vulns: int
    vulnerabilities_fixed: int
    message: str
    output_dir: Optional[Path] = None


@dataclass
class IterationResult:
    """Result of a single iteration."""
    vulns_before: int
    vulns_after: int
    tests_passed: bool
    completed: bool
    output: str


class RalphLoop:
    """The main Ralph loop executor."""

    def __init__(
        self,
        project_path: Path,
        ecosystem: str,
        max_iterations: int = 10,
        completion_token: str = "<COMPLETE>",
        output_dir: Optional[Path] = None,
        prompt_template: Optional[str] = None,
        on_iteration: Optional[Callable[[int, IterationResult], None]] = None,
        dangerously_skip_permissions: bool = False,
    ):
        self.project_path = Path(project_path).resolve()
        self.ecosystem = ecosystem
        self.max_iterations = max_iterations
        self.completion_token = completion_token
        self.output_dir = output_dir or (self.project_path / ".ralph")
        self.prompt_template = prompt_template
        self.on_iteration = on_iteration
        self.dangerously_skip_permissions = dangerously_skip_permissions

        self.scanner: Scanner = get_scanner(ecosystem)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> LoopResult:
        """Execute the Ralph loop."""
        # Check prerequisites
        if not self._check_prerequisites():
            return LoopResult(
                success=False,
                iterations=0,
                initial_vulns=0,
                final_vulns=0,
                vulnerabilities_fixed=0,
                message="Prerequisites check failed",
            )

        # Initial scan
        ui.print_step("Running initial vulnerability scan...")
        initial_vulns = self.scanner.scan(self.project_path)
        initial_count = len(initial_vulns)

        if initial_count == 0:
            ui.print_success(0, 0)
            return LoopResult(
                success=True,
                iterations=0,
                initial_vulns=0,
                final_vulns=0,
                vulnerabilities_fixed=0,
                message="No vulnerabilities found!",
            )

        ui.print_scan_results(
            [v.to_dict() for v in initial_vulns],
            self.ecosystem
        )

        # Build prompt
        prompt = self._build_prompt(initial_vulns)

        # Save prompt for reference
        prompt_file = self.output_dir / "prompt.md"
        prompt_file.write_text(prompt)

        # Run loop
        current_vulns = initial_count
        for iteration in range(1, self.max_iterations + 1):
            ui.print_iteration_start(iteration, self.max_iterations)

            result = self._run_iteration(iteration, prompt, current_vulns)

            if self.on_iteration:
                self.on_iteration(iteration, result)

            ui.print_iteration_result(
                iteration,
                result.vulns_before,
                result.vulns_after,
                result.tests_passed,
                "COMPLETE" if result.completed else "CONTINUING",
            )

            if result.completed:
                vulns_fixed = initial_count - result.vulns_after
                ui.print_success(iteration, vulns_fixed)
                return LoopResult(
                    success=True,
                    iterations=iteration,
                    initial_vulns=initial_count,
                    final_vulns=result.vulns_after,
                    vulnerabilities_fixed=vulns_fixed,
                    message="All vulnerabilities patched!",
                    output_dir=self.output_dir,
                )

            current_vulns = result.vulns_after

        # Max iterations reached
        final_vulns = self.scanner.scan(self.project_path)
        ui.print_failure(f"Max iterations ({self.max_iterations}) reached")
        return LoopResult(
            success=False,
            iterations=self.max_iterations,
            initial_vulns=initial_count,
            final_vulns=len(final_vulns),
            vulnerabilities_fixed=initial_count - len(final_vulns),
            message=f"Did not complete within {self.max_iterations} iterations",
            output_dir=self.output_dir,
        )

    def _check_prerequisites(self) -> bool:
        """Check that required tools are available."""
        # Check Claude CLI
        if not shutil.which("claude"):
            ui.print_error("Claude CLI not found. Install from: https://docs.anthropic.com/claude-code")
            return False

        # Check scanner
        if not self.scanner.is_available():
            ui.print_error(f"Scanner '{self.scanner.name}' not found. Install it first.")
            return False

        # Check dependencies file
        deps_file = self.scanner.get_dependencies_file(self.project_path)
        if not deps_file:
            ui.print_error(f"No dependencies file found for {self.ecosystem} project")
            return False

        return True

    def _run_iteration(self, iteration: int, prompt: str, vulns_before: int) -> IterationResult:
        """Run a single iteration of the loop."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"iteration_{iteration}_{timestamp}.txt"

        # Run Claude
        cmd = ["claude", "--print"]
        if self.dangerously_skip_permissions:
            cmd.append("--dangerously-skip-permissions")

        try:
            result = subprocess.run(
                cmd,
                input=prompt,
                cwd=self.project_path,
                capture_output=True,
                text=True,
                timeout=600,
            )
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            output = "Claude timed out"
        except Exception as e:
            output = f"Error running Claude: {e}"

        # Save output
        output_file.write_text(output)

        # Check completion
        completed = self.completion_token in output

        # Re-scan for vulnerabilities
        new_vulns = self.scanner.scan(self.project_path)
        vulns_after = len(new_vulns)

        # Run tests
        tests_passed, _ = self.scanner.run_tests(self.project_path)

        # Only truly complete if vulns are 0 and tests pass
        if completed and (vulns_after > 0 or not tests_passed):
            completed = False

        return IterationResult(
            vulns_before=vulns_before,
            vulns_after=vulns_after,
            tests_passed=tests_passed,
            completed=completed and vulns_after == 0 and tests_passed,
            output=output,
        )

    def _build_prompt(self, vulnerabilities: list[Vulnerability]) -> str:
        """Build the prompt for Claude."""
        if self.prompt_template:
            return self.prompt_template

        vuln_list = "\n".join([
            f"- {v.package}=={v.version}: {v.id} (fix: {v.fix_version or 'unknown'})"
            for v in vulnerabilities
        ])

        deps_file = self.scanner.get_dependencies_file(self.project_path)
        deps_filename = deps_file.name if deps_file else "dependencies file"

        return f"""# Dependency Vulnerability Patcher

You are an autonomous security agent. Fix ALL dependency vulnerabilities in this project.

## Current Vulnerabilities

{vuln_list}

## Your Task

1. Update `{deps_filename}` with patched versions
2. Run `{self.scanner.name}` to verify fixes
3. Run tests to ensure nothing is broken
4. Repeat until all vulnerabilities are fixed

## Rules

- NEVER remove packages unless they're unused
- NEVER downgrade versions
- If updating breaks tests, try a different version or fix the compatibility issue
- Prefer minimal version bumps that fix the CVE

## Success Criteria

Output `{self.completion_token}` ONLY when:
- All vulnerabilities are fixed (or documented as unfixable)
- All tests pass

Do NOT output the completion token until both conditions are met.
"""
