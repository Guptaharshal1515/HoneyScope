"""Scenario: Race Condition & Business Logic (CWE-362, MITRE T1499)

In-memory coupon application system demonstrating Time-of-Check to Time-of-Use (TOCTOU)
race conditions and locking flaws:
  low        : No locking or atomicity. Check and state update are separated.
  medium     : Lock is placed only around the update, leaving the check unprotected.
  high       : New Lock instance is created per-request, failing to synchronize across threads.
  impossible : Synchronized atomic transaction with shared global mutex protecting check and update.

CONTAINMENT:
  - In-memory data structures only.
  - Safe bounds on balances and iterations.
"""
import threading
import time

# User balances: user_id -> balance
USER_BALANCES: dict[int, int] = {
    1: 100,
    2: 100,
}

# Used coupons: user_id -> set of applied coupon codes
USED_COUPONS: dict[int, set[str]] = {
    1: set(),
    2: set(),
}

# Valid coupons and credit values
COUPONS: dict[str, int] = {
    "PROMO50": 50,
    "SAVE50": 50,
    "WELCOME10": 10,
    "SUMMER5": 5,
}

_SHARED_LOCK = threading.Lock()


def reset_user(user_id: int = 1) -> None:
    """Reset user balance and coupon history."""
    with _SHARED_LOCK:
        USER_BALANCES[user_id] = 100
        USED_COUPONS[user_id] = set()


def get_balance(user_id: int = 1) -> int:
    """Get current user balance."""
    with _SHARED_LOCK:
        return USER_BALANCES.get(user_id, 100)


def apply_coupon(coupon_code: str, user_id: int, level: str) -> tuple[dict, bool]:
    """
    Apply coupon to user account.
    Returns (result_dict, exploited: bool).
    """
    code = (coupon_code or "").strip().upper()
    if code not in COUPONS:
        return {"error": f"Invalid or expired coupon code '{coupon_code}'"}, False

    value = COUPONS[code]

    if level == "low":
        # 1. Check (unprotected)
        user_used = USED_COUPONS.setdefault(user_id, set())
        if code in user_used:
            return {"error": "Coupon already redeemed by user"}, False

        # Small delay window simulating database read / business logic
        time.sleep(0.005)

        # 2. Update (unprotected)
        user_used.add(code)
        new_balance = USER_BALANCES.get(user_id, 100) + value
        USER_BALANCES[user_id] = new_balance

        # Exploitation check: did user receive multiple credits for PROMO50?
        exploited = USER_BALANCES[user_id] > 150
        return {
            "status": "success",
            "message": f"Coupon applied: +${value}",
            "balance": USER_BALANCES[user_id],
        }, exploited

    if level == "medium":
        # Check outside the lock
        user_used = USED_COUPONS.setdefault(user_id, set())
        if code in user_used:
            return {"error": "Coupon already redeemed by user"}, False

        # Context switch window
        time.sleep(0.005)

        # Update inside lock (too late — check was unprotected)
        with _SHARED_LOCK:
            user_used.add(code)
            new_balance = USER_BALANCES.get(user_id, 100) + value
            USER_BALANCES[user_id] = new_balance

        exploited = USER_BALANCES[user_id] > 150
        return {
            "status": "success",
            "message": f"Coupon applied: +${value}",
            "balance": USER_BALANCES[user_id],
        }, exploited

    if level == "high":
        # Flaw: per-request lock (does not block other threads)
        local_lock = threading.Lock()
        with local_lock:
            user_used = USED_COUPONS.setdefault(user_id, set())
            if code in user_used:
                return {"error": "Coupon already redeemed by user"}, False

            time.sleep(0.005)

            user_used.add(code)
            new_balance = USER_BALANCES.get(user_id, 100) + value
            USER_BALANCES[user_id] = new_balance

        exploited = USER_BALANCES[user_id] > 150
        return {
            "status": "success",
            "message": f"Coupon applied: +${value}",
            "balance": USER_BALANCES[user_id],
        }, exploited

    if level == "impossible":
        # Textbook fix: single atomic critical section protecting check and update
        with _SHARED_LOCK:
            user_used = USED_COUPONS.setdefault(user_id, set())
            if code in user_used:
                return {"error": "Coupon already redeemed by user"}, False

            user_used.add(code)
            new_balance = USER_BALANCES.get(user_id, 100) + value
            USER_BALANCES[user_id] = new_balance

            return {
                "status": "success",
                "message": f"Coupon applied: +${value}",
                "balance": USER_BALANCES[user_id],
            }, False

    return {"error": f"Unknown level {level}"}, False
