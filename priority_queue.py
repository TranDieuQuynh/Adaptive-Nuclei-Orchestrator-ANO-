import heapq


class TemplatePriorityQueue:
    def __init__(self):
        self.heap = []
        self.best_scores = {}
        self.counter = 0

    def push_or_update(self, template, score):
        if score == float("-inf"):
            return

        old_score = self.best_scores.get(template.template_id)

        if old_score is not None and old_score >= score:
            return

        self.best_scores[template.template_id] = score
        self.counter += 1

        # heapq là min-heap, dùng -score để thành max-heap
        heapq.heappush(self.heap, (-score, self.counter, template))

    def pop_best(self):
        while self.heap:
            neg_score, _, template = heapq.heappop(self.heap)
            score = -neg_score

            if self.best_scores.get(template.template_id) == score:
                del self.best_scores[template.template_id]
                return template, score

        return None, None

    def empty(self):
        return len(self.best_scores) == 0

    def __len__(self):
        return len(self.best_scores)