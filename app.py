import os
import time
import hmac
import hashlib
import razorpay
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, template_folder='.', static_folder='.')

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")

razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

THIRTY_DAYS_SECONDS = 30 * 24 * 60 * 60


@app.route('/')
def index():
    return render_template('index.html', razorpay_key_id=RAZORPAY_KEY_ID)


@app.route('/api/create-order', methods=['POST'])
def create_order():
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        return jsonify({"error": "Razorpay credentials not configured on server."}), 401

    try:
        data = request.get_json(silent=True) or {}
        amount = int(data.get('amount', 0))  # Expects amount in paise
        currency = data.get('currency', 'INR')
        receipt = data.get('receipt', f'rcpt_{int(time.time())}')

        if amount < 100:
            return jsonify({"error": "Invalid amount. Minimum order amount is 100 paise (₹1)."}), 400

        order_payload = {
            "amount": amount,
            "currency": currency,
            "receipt": receipt,
            "payment_capture": 1
        }

        order = razorpay_client.order.create(data=order_payload)

        return jsonify({
            "order_id": order['id'],
            "amount": order['amount'],
            "currency": order['currency']
        }), 200

    except razorpay.errors.BadRequestError as e:
        err_msg = str(e)
        if "Authentication failed" in err_msg or "authentication" in err_msg.lower():
            return jsonify({"error": "Razorpay authentication failed. Check API keys."}), 401
        return jsonify({"error": err_msg}), 400
    except Exception as e:
        return jsonify({"error": f"Failed to create order: {str(e)}"}), 500


@app.route('/api/verify-payment', methods=['POST'])
def verify_payment():
    if not RAZORPAY_KEY_SECRET:
        return jsonify({"error": "Server secret key missing."}), 401

    try:
        data = request.get_json(silent=True) or {}
        order_id = data.get('razorpay_order_id')
        payment_id = data.get('razorpay_payment_id')
        razorpay_signature = data.get('razorpay_signature')

        if not all([order_id, payment_id, razorpay_signature]):
            return jsonify({"error": "Missing required payment verification fields."}), 400

        # Algorithm: HMAC-SHA256(order_id + "|" + payment_id, KEY_SECRET)
        message = f"{order_id}|{payment_id}".encode('utf-8')
        secret = RAZORPAY_KEY_SECRET.encode('utf-8')
        generated_signature = hmac.new(secret, message, hashlib.sha256).hexdigest()

        if hmac.compare_digest(generated_signature, razorpay_signature):
            expiry_ms = int((time.time() + THIRTY_DAYS_SECONDS) * 1000)
            return jsonify({
                "status": "success",
                "message": "Payment signature verified.",
                "payment_id": payment_id,
                "order_id": order_id,
                "expiry_ms": expiry_ms
            }), 200
        else:
            return jsonify({
                "status": "failure",
                "error": "Payment signature verification failed."
            }), 400

    except Exception as e:
        return jsonify({"error": f"Verification error: {str(e)}"}), 500


@app.route('/api/restore-pass', methods=['POST'])
def restore_pass():
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        return jsonify({"error": "Server credentials not configured."}), 401

    try:
        data = request.get_json(silent=True) or {}
        payment_id = (data.get('payment_id') or '').strip()

        if not payment_id or not payment_id.startswith('pay_'):
            return jsonify({"error": "Please enter a valid Razorpay Payment ID starting with 'pay_'."}), 400

        # Fetch payment details directly from Razorpay's servers
        payment = razorpay_client.payment.fetch(payment_id)

        # 1. Verify payment status
        if payment.get('status') != 'captured':
            return jsonify({"error": f"Payment status is '{payment.get('status')}'. Only captured payments are eligible."}), 400

        # 2. Verify it was a ₹99 Monthly Pro Pass (9900 paise), not the ₹19 single batch
        amount_paid = int(payment.get('amount', 0))
        if amount_paid < 9900:
            return jsonify({"error": "This Payment ID was for a one-time ₹19 batch, not the ₹99 30-Day Pro Pass."}), 400

        # 3. Calculate exact expiration date from Razorpay's payment timestamp
        created_at = int(payment.get('created_at', 0))  # Unix timestamp in seconds
        expiry_timestamp = created_at + THIRTY_DAYS_SECONDS
        now_timestamp = int(time.time())

        if now_timestamp >= expiry_timestamp:
            return jsonify({"error": "This 30-Day Pro Pass has expired."}), 400

        days_left = max(1, int((expiry_timestamp - now_timestamp) // (24 * 60 * 60)))

        return jsonify({
            "status": "success",
            "payment_id": payment_id,
            "expiry_ms": expiry_timestamp * 1000,
            "days_left": days_left
        }), 200

    except razorpay.errors.BadRequestError:
        return jsonify({"error": "Payment ID not found. Please check your Razorpay receipt and try again."}), 404
    except Exception as e:
        return jsonify({"error": f"Could not verify Payment ID: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)