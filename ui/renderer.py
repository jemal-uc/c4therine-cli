import time
import sys
from rich.console import Console
from rich.text import Text
import pyfiglet

console = Console()

class UIRenderer:
    def __init__(self):
        self.color = "bold green"

    def boot_sequence(self):
        ascii_banner = pyfiglet.figlet_format("C4therine")
        console.print(Text(ascii_banner, style=self.color))
        console.print(Text("v0.0.1 - Terminal AI Simulator initialized.\n", style="dim green"))

        modules = [
            "Loading Neural Core...",
            "Loading Memory System...",
            "Loading API Layer...",
            "Loading UI Renderer...",
            "System Ready."
        ]
        
        for module in modules:
            console.print(Text(module, style=self.color))
            time.sleep(0.4)
        console.print("\n")

    def show_thinking(self):
        frames = [
            "[■■□□□□□□□□] Thinking...",
            "[■■■■□□□□□□] Thinking...",
            "[■■■■■■□□□□] Thinking...",
            "[■■■■■■■■□□] Thinking...",
            "[■■■■■■■■■■] Done"
        ]
        
        for frame in frames:
            sys.stdout.write(f"\r\033[92m{frame}\033[0m")
            sys.stdout.flush()
            time.sleep(0.3)
        sys.stdout.write("\r\033[K") # Clear the line

    def type_effect(self, text: str):
        for char in text:
            sys.stdout.write(f"\033[92m{char}\033[0m")
            sys.stdout.flush()
            time.sleep(0.015) # Typing speed
        print("\n")

    def print_system(self, text: str):
        if text:
            console.print(Text(text, style=self.color))