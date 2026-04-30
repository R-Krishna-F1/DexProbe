#!/usr/bin/env python3
"""
core/logger.py — Shared coloured terminal output helpers.
Internal to core/ — not part of the public module surface.
"""

from colorama import Fore, Style, init
init(autoreset=True)

def ok(msg: str)      -> None: print(f"{Fore.GREEN}[OK]{Style.RESET_ALL}    {msg}")
def info(msg: str)    -> None: print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL}  {msg}")
def warn(msg: str)    -> None: print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL}  {msg}")
def err(msg: str)     -> None: print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {msg}")
def step(msg: str)    -> None: print(f"{Fore.MAGENTA}[>>]{Style.RESET_ALL}    {msg}")

def section(title: str, width: int = 54) -> None:
    print(f"\n{Fore.CYAN}{'═' * width}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  {title}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'═' * width}{Style.RESET_ALL}\n")

def divider(title: str = "", width: int = 54) -> None:
    print(f"{Fore.CYAN}{'─' * width}{Style.RESET_ALL}")
    if title:
        print(f"{Fore.CYAN}  {title}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─' * width}{Style.RESET_ALL}")
