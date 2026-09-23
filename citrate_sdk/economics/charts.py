"""
Chart generation for Citrate economic simulation results.

All functions accept a SimulationResult (or dict of results for comparison
charts) and an output path. Charts are rendered via matplotlib and saved
as PNG files at 150 DPI.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from matplotlib.axes import Axes
    from matplotlib.figure import Figure

try:
    import matplotlib

    matplotlib.use("Agg")  # non-interactive backend for headless rendering
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker

    _HAS_MATPLOTLIB = True
except ImportError:
    _HAS_MATPLOTLIB = False

from . import parameters as P
from .simulation import SimulationResult


def _require_matplotlib() -> None:
    if not _HAS_MATPLOTLIB:
        raise ImportError(
            "matplotlib is required for chart generation. "
            "Install it with: pip install matplotlib"
        )


def _epochs_to_years(epochs: np.ndarray) -> np.ndarray:
    """Convert epoch indices to fractional years."""
    return epochs / P.EPOCHS_PER_YEAR


def _setup_figure(
    title: str,
    xlabel: str = "Year",
    ylabel: str = "",
    figsize: tuple[float, float] = (12, 6),
) -> tuple:
    _require_matplotlib()
    fig, ax = plt.subplots(figsize=figsize)
    ax.set_title(title, fontsize=14, fontweight="bold", pad=12)
    ax.set_xlabel(xlabel, fontsize=11)
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=11)
    ax.grid(True, alpha=0.3, linestyle="--")
    return fig, ax


def _add_halving_markers(ax: Axes, max_year: float) -> None:
    """Add vertical lines at halving block heights."""
    halving_year = P.HALVING_INTERVAL * P.BLOCK_TIME_SECONDS / (365.25 * 86400)
    year = halving_year
    halving_num = 1
    while year < max_year and halving_num <= 5:
        ax.axvline(
            x=year,
            color="red",
            linestyle=":",
            alpha=0.5,
            label=f"Halving {halving_num}" if halving_num <= 3 else None,
        )
        year += halving_year
        halving_num += 1


def _save_and_close(fig: Figure, output_path: str) -> None:
    fig.tight_layout()
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Public chart functions
# ---------------------------------------------------------------------------


def plot_supply_curve(result: SimulationResult, output_path: str) -> None:
    """
    10-year supply dynamics: circulating, staked, and burned on same axes.
    """
    arrays = result.to_arrays()
    years = _epochs_to_years(arrays["epoch"])

    fig, ax = _setup_figure(
        f"SALT Supply Dynamics ({result.scenario.title()} Scenario)",
        ylabel="SALT Tokens",
    )

    ax.fill_between(
        years,
        0,
        arrays["total_staked"],
        alpha=0.3,
        color="#6366f1",
        label="Staked",
    )
    ax.fill_between(
        years,
        arrays["total_staked"],
        arrays["total_staked"] + arrays["circulating_supply"],
        alpha=0.3,
        color="#10b981",
        label="Circulating",
    )
    ax.plot(years, arrays["total_burned"], color="#ef4444", linewidth=2, label="Cumulative Burned")
    ax.plot(years, arrays["total_minted"], color="#3b82f6", linewidth=2, linestyle="--", label="Cumulative Minted")

    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x / 1e6:.0f}M"))
    _add_halving_markers(ax, years[-1])
    ax.legend(loc="upper left", fontsize=10)
    _save_and_close(fig, output_path)


def plot_staking_apy(result: SimulationResult, output_path: str) -> None:
    """
    Staking APY over time with halving markers.
    """
    arrays = result.to_arrays()
    years = _epochs_to_years(arrays["epoch"])

    fig, ax1 = _setup_figure(
        f"Staking APY & Ratio ({result.scenario.title()} Scenario)",
        ylabel="APY (%)",
    )

    color_apy = "#6366f1"
    color_ratio = "#10b981"

    ax1.plot(years, arrays["apy"], color=color_apy, linewidth=2, label="Staking APY")
    ax1.set_ylabel("APY (%)", color=color_apy, fontsize=11)
    ax1.tick_params(axis="y", labelcolor=color_apy)

    ax2 = ax1.twinx()
    ax2.plot(
        years,
        arrays["staking_ratio"] * 100,
        color=color_ratio,
        linewidth=2,
        linestyle="--",
        label="Staking Ratio",
    )
    ax2.set_ylabel("Staking Ratio (%)", color=color_ratio, fontsize=11)
    ax2.tick_params(axis="y", labelcolor=color_ratio)

    _add_halving_markers(ax1, years[-1])

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper right", fontsize=10)

    _save_and_close(fig, output_path)


def plot_fee_revenue(result: SimulationResult, output_path: str) -> None:
    """
    Fee revenue over time broken down by source.
    Uses a rolling average to smooth epoch noise.
    """
    arrays = result.to_arrays()
    years = _epochs_to_years(arrays["epoch"])

    fig, ax = _setup_figure(
        f"Protocol Fee Revenue ({result.scenario.title()} Scenario)",
        ylabel="SALT per Epoch",
    )

    # Revenue is already total; plot with smoothing
    window = max(1, len(years) // 100)
    if window > 1:
        kernel = np.ones(window) / window
        fee_smooth = np.convolve(arrays["fee_revenue"], kernel, mode="same")
    else:
        fee_smooth = arrays["fee_revenue"]

    ax.plot(years, fee_smooth, color="#3b82f6", linewidth=2, label="Total Fee Revenue")

    # Overlay the breakdown components
    val_rev = arrays["validator_revenue"]
    creator_rev = arrays["creator_revenue"]
    staker_rev = arrays["staker_revenue"]
    treasury_rev = arrays["treasury_revenue"]

    if window > 1:
        val_rev = np.convolve(val_rev, kernel, mode="same")
        creator_rev = np.convolve(creator_rev, kernel, mode="same")
        staker_rev = np.convolve(staker_rev, kernel, mode="same")
        treasury_rev = np.convolve(treasury_rev, kernel, mode="same")

    ax.fill_between(years, 0, val_rev, alpha=0.2, color="#6366f1", label="Validators (23%)")
    ax.fill_between(years, val_rev, val_rev + creator_rev, alpha=0.2, color="#10b981", label="Creators (30%)")
    ax.fill_between(
        years,
        val_rev + creator_rev,
        val_rev + creator_rev + staker_rev,
        alpha=0.2,
        color="#f59e0b",
        label="Stakers (15%)",
    )

    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:.1f}"))
    ax.legend(loc="upper left", fontsize=9)
    _save_and_close(fig, output_path)


def plot_burn_analysis(result: SimulationResult, output_path: str) -> None:
    """
    Cumulative burned vs minted tokens over time.
    Shows net inflation/deflation trajectory.
    """
    arrays = result.to_arrays()
    years = _epochs_to_years(arrays["epoch"])

    fig, ax = _setup_figure(
        f"Burn vs Mint Analysis ({result.scenario.title()} Scenario)",
        ylabel="SALT Tokens",
    )

    ax.plot(years, arrays["total_minted"], color="#3b82f6", linewidth=2, label="Cumulative Minted")
    ax.plot(years, arrays["total_burned"], color="#ef4444", linewidth=2, label="Cumulative Burned")

    # Net new supply
    net_supply = arrays["total_minted"] - arrays["total_burned"]
    ax.plot(years, net_supply, color="#10b981", linewidth=2, linestyle="--", label="Net Supply Added")

    # Burn rate as percentage
    burn_pct = np.where(
        arrays["total_minted"] > 0,
        arrays["total_burned"] / arrays["total_minted"] * 100,
        0,
    )
    ax2 = ax.twinx()
    ax2.plot(years, burn_pct, color="#f59e0b", linewidth=1.5, linestyle=":", label="Burn % of Minted")
    ax2.set_ylabel("Burn %", color="#f59e0b", fontsize=11)
    ax2.tick_params(axis="y", labelcolor="#f59e0b")

    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x / 1e6:.1f}M"))
    _add_halving_markers(ax, years[-1])

    lines1, labels1 = ax.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax.legend(lines1 + lines2, labels1 + labels2, loc="upper left", fontsize=9)

    _save_and_close(fig, output_path)


def plot_floor_price(result: SimulationResult, output_path: str) -> None:
    """
    SALT floor price from the FLOP oracle alongside market price.
    """
    arrays = result.to_arrays()
    years = _epochs_to_years(arrays["epoch"])

    fig, ax = _setup_figure(
        f"SALT Price & Floor ({result.scenario.title()} Scenario)",
        ylabel="USD",
    )

    ax.plot(years, arrays["salt_price_usd"], color="#6366f1", linewidth=2, label="Market Price")
    ax.plot(
        years,
        arrays["floor_price_usd"],
        color="#ef4444",
        linewidth=2,
        linestyle="--",
        label="Compute Floor Price",
    )

    ax.fill_between(
        years,
        arrays["floor_price_usd"],
        arrays["salt_price_usd"],
        where=arrays["salt_price_usd"] > arrays["floor_price_usd"],
        alpha=0.15,
        color="#10b981",
        label="Premium",
    )
    ax.fill_between(
        years,
        arrays["floor_price_usd"],
        arrays["salt_price_usd"],
        where=arrays["salt_price_usd"] <= arrays["floor_price_usd"],
        alpha=0.15,
        color="#ef4444",
        label="Below Floor",
    )

    ax.set_yscale("log")
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"${x:.4f}"))
    ax.legend(loc="upper left", fontsize=10)
    _save_and_close(fig, output_path)


def plot_death_spiral(
    results: dict[str, SimulationResult],
    output_path: str,
) -> None:
    """
    Overlay low/medium/high scenarios showing sustainability threshold.

    The 'death spiral' zone is where staking APY drops below opportunity cost
    AND price is below the compute floor -- validators leave, security degrades.
    """
    fig, axes = _setup_figure(
        "Sustainability Analysis: Low / Medium / High Adoption",
        ylabel="",
        figsize=(14, 8),
    )

    # Use a 2x1 subplot
    plt.close(fig)
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 10), sharex=True)
    fig.suptitle(
        "Sustainability Analysis: Death Spiral Detection",
        fontsize=14,
        fontweight="bold",
    )

    colors = {"low": "#ef4444", "medium": "#f59e0b", "high": "#10b981"}

    for label, result in results.items():
        arrays = result.to_arrays()
        years = _epochs_to_years(arrays["epoch"])
        color = colors.get(label, "#6366f1")

        # Top: APY
        ax1.plot(years, arrays["apy"], color=color, linewidth=2, label=f"{label.title()} APY")

        # Bottom: Price vs Floor
        ax2.plot(
            years,
            arrays["salt_price_usd"],
            color=color,
            linewidth=2,
            label=f"{label.title()} Price",
        )
        ax2.plot(
            years,
            arrays["floor_price_usd"],
            color=color,
            linewidth=1,
            linestyle=":",
            alpha=0.6,
        )

    # Danger zone on APY chart (below 5% is concerning)
    ax1.axhline(y=5.0, color="#ef4444", linestyle="--", alpha=0.5, label="Danger: 5% APY")
    ax1.set_ylabel("Staking APY (%)", fontsize=11)
    ax1.legend(loc="upper right", fontsize=9)
    ax1.grid(True, alpha=0.3, linestyle="--")

    ax2.set_ylabel("USD Price", fontsize=11)
    ax2.set_xlabel("Year", fontsize=11)
    ax2.set_yscale("log")
    ax2.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"${x:.3f}"))
    ax2.legend(loc="upper left", fontsize=9)
    ax2.grid(True, alpha=0.3, linestyle="--")

    _save_and_close(fig, output_path)


def plot_sensitivity_heatmap(
    results: dict,
    output_path: str,
    x_label: str = "Adoption Rate Multiplier",
    y_label: str = "Staking Ratio Multiplier",
    metric: str = "apy",
    title: str | None = None,
) -> None:
    """
    4x4 (or NxM) grid heatmap: two parameter dimensions mapped to a metric.

    Expected input format:
        results = {
            (x_val, y_val): SimulationResult,
            ...
        }
    """
    _require_matplotlib()

    # Extract unique x and y values
    x_vals = sorted({k[0] for k in results.keys()})
    y_vals = sorted({k[1] for k in results.keys()})

    grid = np.zeros((len(y_vals), len(x_vals)))
    for (xv, yv), res in results.items():
        xi = x_vals.index(xv)
        yi = y_vals.index(yv)
        arrays = res.to_arrays()
        if metric in arrays and len(arrays[metric]) > 0:
            # Use the final value
            grid[yi, xi] = arrays[metric][-1]
        elif hasattr(res.final, metric):
            grid[yi, xi] = getattr(res.final, metric)

    fig, ax = plt.subplots(figsize=(10, 8))
    title_text = title or f"Sensitivity: {metric.upper()} at Year {res.total_years}"
    ax.set_title(title_text, fontsize=14, fontweight="bold", pad=12)

    im = ax.imshow(grid, aspect="auto", cmap="RdYlGn", origin="lower")
    fig.colorbar(im, ax=ax, label=metric.upper())

    ax.set_xticks(range(len(x_vals)))
    ax.set_xticklabels([f"{v:.1f}" for v in x_vals])
    ax.set_yticks(range(len(y_vals)))
    ax.set_yticklabels([f"{v:.1f}" for v in y_vals])
    ax.set_xlabel(x_label, fontsize=11)
    ax.set_ylabel(y_label, fontsize=11)

    # Annotate cells
    for yi in range(len(y_vals)):
        for xi in range(len(x_vals)):
            val = grid[yi, xi]
            ax.text(
                xi,
                yi,
                f"{val:.1f}",
                ha="center",
                va="center",
                fontsize=9,
                color="black" if val > grid.mean() else "white",
            )

    _save_and_close(fig, output_path)


def plot_revenue_breakdown(result: SimulationResult, output_path: str) -> None:
    """
    Stacked area chart of the 7-way revenue split over time.
    """
    arrays = result.to_arrays()
    years = _epochs_to_years(arrays["epoch"])

    fig, ax = _setup_figure(
        f"Revenue Distribution ({result.scenario.title()} Scenario)",
        ylabel="SALT per Epoch",
    )

    # Smooth the data for visual clarity
    window = max(1, len(years) // 80)
    kernel = np.ones(window) / window

    def smooth(arr: np.ndarray) -> np.ndarray:
        if window > 1:
            return np.convolve(arr, kernel, mode="same")
        return arr

    val_rev = smooth(arrays["validator_revenue"])
    creator_rev = smooth(arrays["creator_revenue"])
    infra_rev = smooth(arrays["infra_revenue"])
    treasury_rev = smooth(arrays["treasury_revenue"])
    staker_rev = smooth(arrays["staker_revenue"])
    facilitator_rev = smooth(arrays["facilitator_revenue"])

    # Stack order: bottom to top
    layers = [val_rev, creator_rev, infra_rev, treasury_rev, staker_rev, facilitator_rev]
    labels = [
        "Validators (23%)",
        "Model Creators (30%)",
        "Infrastructure (15%)",
        "Treasury (12%)",
        "Stakers (15%)",
        "Facilitators (5%)",
    ]
    colors = ["#6366f1", "#10b981", "#3b82f6", "#f59e0b", "#8b5cf6", "#ec4899"]

    ax.stackplot(years, *layers, labels=labels, colors=colors, alpha=0.7)
    ax.legend(loc="upper left", fontsize=9, ncol=2)
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda x, _: f"{x:.2f}"))
    _save_and_close(fig, output_path)
