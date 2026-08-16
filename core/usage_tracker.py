class UsageTracker:
    def __init__(self):
        self.input_tokens = 0
        self.output_tokens = 0
        self.budget_limit = None # Dalam nominal tertentu (misal USD)
        self.cost_per_1k_input = 0.00005 # Estimasi biaya model
        self.cost_per_1k_output = 0.00008

    def add_usage(self, input_tk: int, output_tk: int):
        self.input_tokens += input_tk
        self.output_tokens += output_tk

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def estimated_cost(self) -> float:
        in_cost = (self.input_tokens / 1000) * self.cost_per_1k_input
        out_cost = (self.output_tokens / 1000) * self.cost_per_1k_output
        return in_cost + out_cost

    def set_budget(self, limit: float):
        self.budget_limit = limit

    def check_budget(self) -> str:
        if self.budget_limit is None:
            return "ok"
        
        usage_percent = (self.estimated_cost / self.budget_limit) * 100
        if usage_percent >= 100:
            return "exceeded"
        elif usage_percent >= 80:
            return "warning"
        return "ok"