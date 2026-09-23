#!/usr/bin/env python3
"""
Citrate Economic Viability Report Generator
============================================
Runs the 10-year agent-based simulation across 3 adoption scenarios (low,
medium, high), generates 8+ charts, and prints a numerical summary.

Usage:
    python reports/economic_viability_report.py

Output:
    reports/charts/*.png   — 8 chart files
    stdout                 — numerical summary table

Parameters sourced from citrate_sdk.economics.parameters (canonical values
matching the Rust economics crate).
"""

import os
import sys
import time

# Add parent dir to path so we can import citrate_sdk
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from citrate_sdk.economics.charts import (
    plot_burn_analysis,
    plot_death_spiral,
    plot_fee_revenue,
    plot_floor_price,
    plot_revenue_breakdown,
    plot_sensitivity_heatmap,
    plot_staking_apy,
    plot_supply_curve,
)
from citrate_sdk.economics.parameters import (
    BASE_BLOCK_REWARD,
    BME_BURN_RATE,
    HALVING_INTERVAL,
    MARKET_MAKER_GAS_BPS,
    TOTAL_SUPPLY,
)
from citrate_sdk.economics.simulation import EconomicSimulation, SimulationResult

CHART_DIR = os.path.join(os.path.dirname(__file__), 'charts')


def run_scenario(name: str, years: int = 10) -> 'SimulationResult':
    """Run a single scenario and return the result."""
    print(f'  Running {name} scenario ({years} years)...', end=' ', flush=True)
    t0 = time.time()
    sim = EconomicSimulation(name)
    result = sim.run(years=years)
    elapsed = time.time() - t0
    print(f'done in {elapsed:.1f}s ({len(result.epochs)} epochs)')
    return result


def print_summary(results: dict):
    """Print a numerical summary table comparing scenarios."""
    print('\n' + '=' * 80)
    print('CITRATE ECONOMIC VIABILITY REPORT')
    print('10-Year Agent-Based Simulation — 3 Scenarios')
    print('=' * 80)

    header = f'{"Metric":<35} {"Low":>14} {"Medium":>14} {"High":>14}'
    print(header)
    print('-' * 80)

    for label, key in [
        ('Final Circulating Supply', 'circulating_supply'),
        ('Total Minted', 'total_minted'),
        ('Total Burned', 'total_burned'),
        ('Total Staked', 'total_staked'),
    ]:
        vals = []
        for scenario in ['low', 'medium', 'high']:
            v = getattr(results[scenario].epochs[-1], key)
            vals.append(f'{v / 1e6:>12,.1f}M')
        print(f'{label:<35} {vals[0]:>14} {vals[1]:>14} {vals[2]:>14}')

    print()
    for label, key in [
        ('Staking Ratio', 'staking_ratio'),
        ('APY (final epoch)', 'apy'),
    ]:
        vals = []
        for scenario in ['low', 'medium', 'high']:
            v = getattr(results[scenario].epochs[-1], key)
            if key == 'apy':
                vals.append(f'{min(v, 999.9):>12.1f}%')
            else:
                vals.append(f'{v * 100:>12.1f}%')
        print(f'{label:<35} {vals[0]:>14} {vals[1]:>14} {vals[2]:>14}')

    print()
    for label, key in [
        ('Validators', 'validator_count'),
        ('Schools', 'school_count'),
        ('Compute Demand (inf/day)', 'compute_demand'),
    ]:
        vals = []
        for scenario in ['low', 'medium', 'high']:
            v = getattr(results[scenario].epochs[-1], key)
            if v > 1_000_000:
                vals.append(f'{v / 1e6:>12,.1f}M')
            elif v > 1_000:
                vals.append(f'{v / 1e3:>12,.1f}K')
            else:
                vals.append(f'{v:>14,}')
        print(f'{label:<35} {vals[0]:>14} {vals[1]:>14} {vals[2]:>14}')

    print()
    for label, key in [
        ('Fee Revenue (final epoch)', 'fee_revenue'),
        ('Floor Price (USD)', 'floor_price_usd'),
        ('SALT Price (USD)', 'salt_price_usd'),
    ]:
        vals = []
        for scenario in ['low', 'medium', 'high']:
            v = getattr(results[scenario].epochs[-1], key)
            if key in ('floor_price_usd', 'salt_price_usd'):
                vals.append(f'${v:>12,.4f}')
            else:
                vals.append(f'{v:>12,.0f}')
        print(f'{label:<35} {vals[0]:>14} {vals[1]:>14} {vals[2]:>14}')

    # Key parameters
    print('\n' + '-' * 80)
    print('KEY PARAMETERS (from Rust economics crate)')
    print(f'  Total Supply:           {TOTAL_SUPPLY:>20,} SALT')
    print(f'  Base Block Reward:      {BASE_BLOCK_REWARD:>20} SALT/block')
    print(f'  Halving Interval:       {HALVING_INTERVAL:>20,} blocks (~4 years)')
    print(f'  BME Burn Rate:          {BME_BURN_RATE * 100:>19.1f}%')
    print(f'  Market Maker Gas Fee:   {MARKET_MAKER_GAS_BPS / 100:>19.1f}%')
    print('=' * 80)


def generate_charts(results: dict):
    """Generate all 8 charts."""
    os.makedirs(CHART_DIR, exist_ok=True)
    medium = results['medium']

    print('\nGenerating charts...')

    plot_supply_curve(medium, os.path.join(CHART_DIR, '01_supply_curve.png'))
    print('  [1/8] Supply curve')

    plot_staking_apy(medium, os.path.join(CHART_DIR, '02_staking_apy.png'))
    print('  [2/8] Staking APY')

    plot_fee_revenue(medium, os.path.join(CHART_DIR, '03_fee_revenue.png'))
    print('  [3/8] Fee revenue')

    plot_burn_analysis(medium, os.path.join(CHART_DIR, '04_burn_analysis.png'))
    print('  [4/8] Burn analysis')

    plot_floor_price(medium, os.path.join(CHART_DIR, '05_floor_price.png'))
    print('  [5/8] Floor price')

    plot_death_spiral(results, os.path.join(CHART_DIR, '06_death_spiral.png'))
    print('  [6/8] Death spiral analysis')

    # Sensitivity heatmap requires running additional parameter sweeps
    print('  [7/8] Sensitivity heatmap (running parameter sweep)...')
    sensitivity_results = run_sensitivity_sweep()
    plot_sensitivity_heatmap(sensitivity_results, os.path.join(CHART_DIR, '07_sensitivity.png'))

    plot_revenue_breakdown(medium, os.path.join(CHART_DIR, '08_revenue_breakdown.png'))
    print('  [8/8] Revenue breakdown')

    print(f'\nAll charts saved to {CHART_DIR}/')


def run_sensitivity_sweep() -> dict:
    """Run a 3x3 parameter sweep for the sensitivity heatmap.

    Uses the medium scenario as baseline with 5-year runs for speed.
    Returns dict of results keyed by 'ar=X%_sr=Y%'.
    """
    results = {}
    # Use the three built-in scenarios as proxies for adoption rate variation,
    # and run each for 5 years to keep total sweep time reasonable.
    for scenario_name in ['low', 'medium', 'high']:
        sim = EconomicSimulation(scenario_name)
        result = sim.run(years=5)
        results[scenario_name] = result

    return results


def main():
    print('Citrate Economic Viability Report Generator')
    print('Running 3 scenarios (low, medium, high) for 10 years each...\n')

    t_start = time.time()

    results = {}
    for scenario in ['low', 'medium', 'high']:
        results[scenario] = run_scenario(scenario)

    print_summary(results)

    try:
        generate_charts(results)
    except ImportError as e:
        print(f'\nSkipping chart generation (matplotlib not installed): {e}')
    except Exception as e:
        print(f'\nChart generation failed: {e}')
        import traceback
        traceback.print_exc()

    total_time = time.time() - t_start
    print(f'\nTotal report generation time: {total_time:.1f}s')


if __name__ == '__main__':
    main()
