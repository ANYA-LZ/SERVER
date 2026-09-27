"""
ANYA Payment Gateway Server — V5.1.0
Flask server handling payment processing with session isolation.
Communicates with the Telegram bot via REST API.
"""

import sys
import os

_srv_dir = os.path.dirname(os.path.abspath(__file__))
if _srv_dir not in sys.path:
    sys.path.insert(0, _srv_dir)

import logging
from flask import Flask

from core.session import SessionManager
from core.geo import generate_random_person
from core.proxy import parse_proxy, categorize_proxy_error, is_proxy_error, ProxyConnectionError
from gateways.stripe_auth import handle_stripe_auth
from gateways.stripe_charge import handle_stripe_charge
from gateways.braintree import handle_braintree_auth
from gateways.adyen import handle_adyen_charge
from gateways.ds3 import handle_3ds_lookup

app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

session_manager = SessionManager()

APPROVED = "𝘼𝙥𝙥𝙧𝙤𝙫𝙚𝙙 ✅"
DECLINED = "𝘿𝙚𝙘𝙡𝙞𝙣𝙚𝙙 ❌"
ERROR = "𝙀𝙍𝙍𝙊𝙍 ⚠️"
SUCCESS = "𝙎𝙐𝘾𝘾𝞢𝙎𝙎 ✅"
FAILED = "𝙁𝘼𝙄𝙇𝙀𝘿 ❌"
INSUFFICIENT_FUNDS = "𝙄𝙣𝙨𝙪𝙛𝙛𝙞𝙘𝙞𝙚𝙣𝙩 𝙁𝙪𝙣𝙙𝙨 ☑️"
PASSAD = "𝙋𝘼𝙎𝙎𝙀𝘿 ❎"

GATEWAY_HANDLERS = {
    "Braintree Auth": handle_braintree_auth,
    "Stripe Auth":    handle_stripe_auth,
    "Stripe Charge":  handle_stripe_charge,
    "Adyen Charge":   handle_adyen_charge,
    "3DS Lookup":     handle_3ds_lookup,
}


@app.route("/payment", methods=["POST"])
def process_payment():
    """Main payment endpoint receiving card + gateway config from the bot."""
    from flask import request, jsonify
    try:
        body = request.get_json(force=True)
        card_info = body.get("card", {})
        gateway_config = body.get("gateway_config", {})

        if not card_info or not gateway_config:
            return jsonify({"status": ERROR, "result": "Invalid request: missing card or gateway_config"}), 400

        gateway_type = gateway_config.get("gateway_type", "")
        handler = GATEWAY_HANDLERS.get(gateway_type)
        if not handler:
            return jsonify({"status": ERROR, "result": f"Unknown gateway type: {gateway_type}"}), 400

        person = generate_random_person()
        status, result = handler(card_info, person, gateway_config)

        if status == ERROR:
            return jsonify({"status": status, "result": result}), 400 
        else:
            return jsonify({"status": status, "result": result}), 200

    except Exception as exc:
        logger.error(f"Payment error: {exc}")
        return jsonify({"status": ERROR, "result": f"Server error: {exc}"}), 500


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint for the bot to verify server availability."""
    from flask import jsonify
    return jsonify({
        "status": "ok",
        "active_sessions": session_manager.get_active_sessions_count(),
        "gateways": list(GATEWAY_HANDLERS.keys()),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
