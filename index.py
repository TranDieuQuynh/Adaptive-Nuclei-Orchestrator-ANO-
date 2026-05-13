class SignatureIndex:
    """
    Inverted index:
    - (type, value) -> templates
    - (type, "*") -> templates

    Example:
    - ("tech", "wordpress") -> [wp-version-detect, wp-cve-check]
    - ("url", "*") -> [http-detect]
    """

    def __init__(self, templates):
        self.templates = {t.template_id: t for t in templates}
        self.index = {}
        self.build(templates)

    def add_index(self, key, template_id):
        self.index.setdefault(key, set()).add(template_id)

    def build(self, templates):
        for template in templates:
            for input_type in (template.sieves.inputs or []):
                self.add_index((input_type, "*"), template.template_id)

            for cond in (template.sieves.conditions or []):
                if str(cond.operator).lower() == "eq" and cond.value is not None:
                    self.add_index((cond.type, str(cond.value).lower()), template.template_id)
                else:
                    self.add_index((cond.type, "*"), template.template_id)

            for tag in (template.info.tags or []):
                self.add_index(("tag", tag.lower()), template.template_id)

    def lookup(self, fact):
        keys = [
            (fact.type, str(fact.value).lower()),
            (fact.type, "*"),
        ]

        for tag in fact.tags:
            keys.append(("tag", tag.lower()))

        template_ids = set()
        for key in keys:
            template_ids.update(self.index.get(key, set()))

        return [self.templates[tid] for tid in template_ids]