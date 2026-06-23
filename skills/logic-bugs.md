# SKILL: Business Logic Testing
**The bugs no scanner finds. Requires human (and AI) reasoning about what the app is SUPPOSED to do.**

---

## CORE CONCEPT

Business logic bugs exist when the application does exactly what the code says,
but the code doesn't enforce what the business intended.

**Ask for every feature:** "What is this feature SUPPOSED to prevent? Can I circumvent that?"

---

## FINANCIAL / E-COMMERCE LOGIC

```bash
# Price manipulation
# 1. Negative quantity: qty=-1 → refund instead of charge?
# 2. Zero price: modify price param in POST body to 0
# 3. Currency confusion: $1 USD vs $1 JPY in international apps
# 4. Rounding exploit: $0.001 × 1000 = $1 total but charged 1000×$0.00 = $0?
# 5. Integer overflow: extremely large quantities

# Discount code abuse
# 1. Apply same code multiple times (race condition)
# 2. Apply code after payment is initiated
# 3. Combine non-stackable codes via request manipulation
# 4. Apply code to items it shouldn't apply to

# Refund logic
# 1. Refund digital goods (already consumed) 
# 2. Refund partial orders multiple times
# 3. Refund + keep delivery
# 4. Refund amount > original purchase via currency confusion
```

---

## RACE CONDITIONS

```bash
# Targets: coupon redemption, referral bonuses, account credits, vote counts, inventory

# Method 1: Burp Suite Turbo Intruder (most reliable)
# In Turbo Intruder: use "race-single-packet-attack" template

# Method 2: Parallel curl
ENDPOINT="https://{TARGET}/api/redeem"
TOKEN="{YOUR_TOKEN}"
PAYLOAD='{"coupon":"SAVE50"}'

# Launch 20 simultaneous requests
for i in $(seq 1 20); do
  curl -sk -X POST "$ENDPOINT" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" >> sessions/{DATE}/race-results.txt &
done
wait
cat sessions/{DATE}/race-results.txt | sort | uniq -c

# Method 3: Python asyncio for maximum parallelism
python3 scripts/race-tester.py --url $ENDPOINT --token $TOKEN --payload "$PAYLOAD" --threads 50
```

---

## WORKFLOW BYPASS

```bash
# Most multi-step processes can be attacked by:
# 1. Skipping steps: go directly from step 1 to step 3
# 2. Repeating steps: complete step 2 twice
# 3. Going backwards: complete step 3, then re-do step 2
# 4. Modifying state between steps

# Example: Checkout flow
# Step 1: Add to cart
# Step 2: Enter shipping info  
# Step 3: Enter payment info
# Step 4: Confirm order

# Attacks:
# - Skip payment (go from step 2 directly to step 4 request)
# - Swap payment method after price calculation
# - Change cart contents after price is confirmed but before charge
# - Use another user's saved payment method (IDOR on payment method ID)
```

---

## ACCOUNT / SUBSCRIPTION LOGIC

```bash
# Free tier feature abuse
# 1. Exceed limits after downgrade (cancel subscription but keep features)
# 2. Trial abuse: does creating new account reset trial?
# 3. Feature flag leakage: are premium features hidden in HTML/JS but not access-controlled?

# Referral system abuse
# 1. Self-referral: refer yourself with different email
# 2. Referral bonus with immediate refund
# 3. Credit accumulation via race condition on referral endpoint

# Account merging/linking
# 1. Link attacker-controlled OAuth account to victim account
# 2. Email change without verification (if no confirmation required)
# 3. Secondary email as alias to take over primary
```

---

## TIME-BASED LOGIC

```bash
# Token/session timing
# 1. Does password reset token expire properly?
# 2. Does "remember me" token have reasonable lifetime?
# 3. After password change, are all other sessions invalidated?

# Time-of-check to time-of-use (TOCTOU)
# 1. Check balance → transfer → check was done before balance updated
# 2. Verify code → use code → verification state not atomic

# Scheduled operations
# 1. Can future-dated operations be accelerated?
# 2. Are past-dated operations possible (back-dating invoices/records)?
```

---

## LOGIC BUG DISCOVERY METHODOLOGY

```
1. READ THE PROGRAM POLICY — understand what features exist
2. MAP THE HAPPY PATH — do every feature as intended, capture all requests
3. FOR EACH FEATURE, ASK:
   - What is the server TRUSTING from the client?
   - What state transitions does this feature assume?
   - What happens if I complete step N+1 without step N?
   - What happens if I send this request twice?
   - What happens with boundary values? (0, -1, MAX_INT, empty, null)
   - What happens if I send this as a different user?
   - Is there a time window between check and action?
4. TEST YOUR HYPOTHESES with actual requests
5. DOCUMENT the gap between intended and actual behavior
```

---

## HIGH-VALUE LOGIC FINDINGS

| Finding | Typical Severity | Programs that pay well |
|---------|-----------------|----------------------|
| Payment bypass | Critical | Fintech, e-commerce |
| Coupon/credit race condition | High | SaaS, retail |
| Privilege retention after downgrade | High | SaaS |
| Self-referral bonus abuse | Medium | Any referral program |
| OTP/token reuse | High | Any app with MFA |
| Workflow step skip | High | E-commerce, fintech |
| Integer overflow in financial calc | Critical | Fintech |
