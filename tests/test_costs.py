from copy import deepcopy
import unittest

import harp_costs


class CostTests(unittest.TestCase):
    def session(self):
        return {"config": {"oracle": {"provider": "zai", "model": "glm-oracle"},
                           "local": {"provider": "zai", "model": "glm-proxy"}},
                "oracle_calls": [{"model": "glm-oracle", "prompt_tokens": 1000,
                    "cached_input_tokens": 600, "cache_write_tokens": 200,
                    "completion_tokens": 100, "estimated_usd": None}],
                "local_calls": [{"model": "glm-proxy", "prompt_tokens": 2000,
                    "completion_tokens": 200, "usage_reported": True, "estimated_usd": None}]}

    def config(self):
        prices = dict(zip(harp_costs.PRICE_FIELDS, (2, .5, 2.5, 8)))
        return {role: {**model, **prices} for role, model in self.session()["config"].items()}

    def test_late_prices_calculate_both_models_without_mutating_ledger(self):
        session = self.session()
        before = deepcopy(session)
        cost = harp_costs.cost_summary(session, self.config())
        self.assertAlmostEqual(cost["oracle_estimated_usd"], .002)
        self.assertAlmostEqual(cost["local_estimated_usd"], .0056)
        self.assertEqual(cost["oracle_cost_basis"], "current_configured_prices")
        self.assertEqual(session, before)

    def test_different_model_or_provider_does_not_use_current_prices(self):
        for field, value in (("model", "different-model"), ("provider", "openai")):
            config = self.config()
            config["oracle"][field] = value
            self.assertIsNone(harp_costs.cost_summary(self.session(), config)["oracle_estimated_usd"])

    def test_matching_prices_work_after_swapping_roles(self):
        config = self.config()
        config["oracle"], config["local"] = config["local"], config["oracle"]
        self.assertAlmostEqual(harp_costs.cost_summary(self.session(), config)["oracle_estimated_usd"], .002)

    def test_unknown_used_rate_stays_unknown_but_unused_rates_are_optional(self):
        config = self.config()
        config["oracle"]["cached_input_usd_per_million"] = None
        config["local"]["cached_input_usd_per_million"] = None
        config["local"]["cache_write_usd_per_million"] = None
        cost = harp_costs.cost_summary(self.session(), config)
        self.assertIsNone(cost["oracle_estimated_usd"])
        self.assertAlmostEqual(cost["local_estimated_usd"], .0056)

    def test_zero_rates_are_valid_and_missing_usage_is_unknown(self):
        config = self.config()
        config["local"].update({field: 0 for field in harp_costs.PRICE_FIELDS})
        session = self.session()
        self.assertEqual(harp_costs.cost_summary(session, config)["local_estimated_usd"], 0)
        session["local_calls"][0]["usage_reported"] = False
        self.assertIsNone(harp_costs.cost_summary(session, config)["local_estimated_usd"])

    def test_invalid_rates_do_not_make_false_estimates(self):
        for invalid in (-1, float("nan"), float("inf"), "invalid"):
            config = self.config()
            config["local"]["output_usd_per_million"] = invalid
            self.assertIsNone(harp_costs.cost_summary(self.session(), config)["local_estimated_usd"])

    def test_stored_prices_and_recorded_estimates_remain_available(self):
        session = self.session()
        session["config"] = self.config()
        self.assertAlmostEqual(harp_costs.cost_summary(session, {})["oracle_estimated_usd"], .002)
        session = self.session()
        session["oracle_calls"][0]["estimated_usd"] = .123
        self.assertEqual(harp_costs.cost_summary(session, {})["oracle_estimated_usd"], .123)

    def test_hybrid_total_and_same_workload_savings_include_percent(self):
        config = self.config()
        config["local"].update(dict(zip(harp_costs.PRICE_FIELDS, (.1, .02, .125, .4))))
        cost = harp_costs.cost_summary(self.session(), config)
        self.assertEqual(cost["total_estimated_usd"], .00228)
        self.assertEqual(cost["oracle_only_estimated_usd"], .0076)
        self.assertEqual(cost["hybrid_savings_usd"], .00532)
        self.assertEqual(cost["hybrid_savings_percent"], 70)

    def test_negative_savings_are_preserved(self):
        config = self.config()
        config["local"]["output_usd_per_million"] = 100
        cost = harp_costs.cost_summary(self.session(), config)
        self.assertLess(cost["hybrid_savings_usd"], 0)
        self.assertLess(cost["hybrid_savings_percent"], 0)

    def test_zero_baseline_missing_prices_and_nonhybrid(self):
        config = self.config()
        for role in config:
            config[role].update({field: 0 for field in harp_costs.PRICE_FIELDS})
        cost = harp_costs.cost_summary(self.session(), config)
        self.assertEqual(cost["oracle_only_estimated_usd"], 0)
        self.assertEqual(cost["hybrid_savings_usd"], 0)
        self.assertIsNone(cost["hybrid_savings_percent"])
        self.assertIsNone(harp_costs.cost_summary(self.session(), {})["hybrid_savings_usd"])
        session = self.session()
        session.update(mode="frontier-only", local_calls=[])
        cost = harp_costs.cost_summary(session, self.config())
        self.assertEqual(cost["total_estimated_usd"], .002)
        self.assertIsNone(cost["hybrid_savings_percent"])

    def test_unknown_usage_never_shows_partial_total_or_savings(self):
        session = self.session()
        session["local_calls"][0]["usage_reported"] = False
        cost = harp_costs.cost_summary(session, self.config())
        self.assertIsNone(cost["total_estimated_usd"])
        self.assertIsNone(cost["oracle_only_estimated_usd"])
        self.assertIsNone(cost["hybrid_savings_percent"])
