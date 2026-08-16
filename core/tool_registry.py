class ToolRegistry:
    def __init__(self):
        self._tools = {}

    def register(self, name: str, tool_instance):
        """Mendaftarkan tool baru ke dalam sistem."""
        self._tools[name] = tool_instance

    def execute(self, name: str, **kwargs):
        """Menjalankan tool jika terdaftar, semua parameter dikirim sebagai kwargs."""
        if name not in self._tools:
            raise ValueError(f"Tool '{name}' tidak ditemukan di registry.")
        return self._tools[name].execute(**kwargs)

    def get_available_tools(self):
        return list(self._tools.keys())