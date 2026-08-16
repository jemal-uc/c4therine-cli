from ddgs import DDGS

class SearchTool:
    def __init__(self):
        self.name = "search"
        
    def execute(self, query: str, max_results: int = 10) -> dict:
        try:
            with DDGS() as ddgs:
                results = list(ddgs.text(query, max_results=max_results))
                formatted_results = []
                for res in results:
                    formatted_results.append({
                        "title": res.get('title'),
                        "link": res.get('href'),
                        "snippet": res.get('body')
                    })
                return {"status": "success", "data": formatted_results}
        except Exception as e:
            return {"status": "error", "message": str(e)}