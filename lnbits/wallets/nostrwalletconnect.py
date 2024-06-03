import asyncio
import hashlib
import json
import time
from asyncio import Queue
from threading import Thread
from typing import AsyncGenerator, Callable, Dict, List, Optional

from loguru import logger
from pydantic import BaseModel
from secp256k1 import PublicKey
from websocket import WebSocketApp

from lnbits.helpers import urlsafe_short_hash
from lnbits.nostrhelpers import (
    decrypt_message,
    derive_public_key,
    encrypt_message,
    get_shared_secret,
    sign_message_hash,
)
from lnbits.settings import settings

from .base import (
    InvoiceResponse,
    PaymentResponse,
    PaymentStatus,
    StatusResponse,
    Wallet,
)


class NostrEvent(BaseModel):
    id: str = ""
    pubkey: str
    created_at: int
    kind: int
    tags: List[List[str]] = []
    content: str = ""
    sig: Optional[str]

    def serialize(self) -> List:
        return [0, self.pubkey, self.created_at, self.kind, self.tags, self.content]

    def serialize_json(self) -> str:
        e = self.serialize()
        return json.dumps(e, separators=(",", ":"), ensure_ascii=False)

    @property
    def event_id(self) -> str:
        data = self.serialize_json()
        event_id = hashlib.sha256(data.encode()).hexdigest()
        return event_id

    def check_signature(self):
        event_id = self.event_id
        if self.id != event_id:
            raise ValueError(
                f"Invalid event id. Expected: '{event_id}' got '{self.id}'"
            )
        try:
            pub_key = PublicKey(bytes.fromhex("02" + self.pubkey), True)
        except Exception as err:
            raise ValueError(
                f"Invalid public key: '{self.pubkey}' for event '{self.id}'"
            ) from err

        valid_signature = pub_key.schnorr_verify(
            bytes.fromhex(event_id), bytes.fromhex(self.sig), None, raw=True
        )
        if not valid_signature:
            raise ValueError(f"Invalid signature: '{self.sig}' for event '{self.id}'")

    def stringify(self) -> str:
        return json.dumps(dict(self))

    def tag_values(self, tag_name: str) -> List[str]:
        return [t[1] for t in self.tags if t[0] == tag_name]

    def has_tag_value(self, tag_name: str, tag_value: str) -> bool:
        return tag_value in self.tag_values(tag_name)


class EventKind:
    WALLET_CONNECT_INFO = 13194
    WALLET_CONNECT_REQUEST = 23194
    WALLET_CONNECT_RESPONSE = 23195


class NostrClient:
    def __init__(self):
        self.recieve_event_queue: Queue = Queue()
        self.send_req_queue: Queue = Queue()
        self.ws: WebSocketApp = None
        self.subscription_id = "nostrmarket-" + urlsafe_short_hash()[:32]
        self.relay = settings.nostr_wallet_connect_relay
        self.connected_event = asyncio.Event()

    async def connect_to_nostrclient_ws(
        self, on_open: Callable, on_message: Callable
    ) -> WebSocketApp:
        def on_error(_, error):
            logger.warning(error)

        def on_open_wrapper(ws):
            self.connected_event.set()  # Set the event here
            if on_open:
                on_open(ws)

        logger.debug("Subscribing to websockets for nostrclient extension")
        logger.debug("Relay: " + self.relay)
        ws = WebSocketApp(
            self.relay,
            on_message=on_message,
            on_open=on_open_wrapper,
            on_error=on_error,
        )

        wst = Thread(target=ws.run_forever)
        wst.daemon = True
        wst.start()

        return ws

    async def get_event(self):
        value = await self.recieve_event_queue.get()
        if isinstance(value, ValueError):
            raise value
        return value

    async def run_forever(self):
        def on_open(_):
            logger.info("Connected to 'nostrclient' websocket")

        def on_message(_, message):
            self.recieve_event_queue.put_nowait(message)

        running = True

        while running:
            try:
                req = None
                if not self.ws:
                    self.ws = await self.connect_to_nostrclient_ws(on_open, on_message)
                    # be sure the connection is open
                    await asyncio.sleep(3)
                elif self.ws.sock and not self.ws.sock.connected:
                    self.ws = await self.connect_to_nostrclient_ws(on_open, on_message)
                    # be sure the connection is open
                    await asyncio.sleep(3)
                req = await self.send_req_queue.get()

                if isinstance(req, ValueError):
                    running = False
                    logger.warning(str(req))
                else:
                    self.ws.send(json.dumps(req))
            except Exception as ex:
                logger.warning(ex)
                if req:
                    await self.send_req_queue.put(req)
                self.ws = None  # todo close
                await asyncio.sleep(5)

    async def publish_nostr_event(self, e: NostrEvent):
        await self.send_req_queue.put(["EVENT", e.dict()])

    async def subscribe_wallet_service(
        self,
        public_keys: List[str],
        recipient_public_keys: Optional[List[str]] = None,
    ):
        nwc_time = int(time.time())
        nwc_filters = self._filters_for_nostr_wallet_connect_messages(
            public_keys, nwc_time, recipient_public_keys
        )

        self.subscription_id = "nostrwalletconnect-" + urlsafe_short_hash()[:32]
        await self.send_req_queue.put(["REQ", self.subscription_id, *nwc_filters])
        # log nwc_filters
        logger.debug(nwc_filters)

        logger.debug(f"Subscribed to events for {len(public_keys)} keys")
        logger.debug(f"Subscription: {self.subscription_id}")

    def _filters_for_nostr_wallet_connect_messages(
        self,
        authors_public_keys: List[str],
        since: int,
        recipient_public_keys: List[str],
    ) -> List:
        out_messages_filter = {
            "kinds": [
                EventKind.WALLET_CONNECT_INFO,
                EventKind.WALLET_CONNECT_REQUEST,
                EventKind.WALLET_CONNECT_RESPONSE,
            ],
            "authors": authors_public_keys,
            "#p": recipient_public_keys,
        }
        if since and since != 0:
            out_messages_filter["since"] = since

        return [out_messages_filter]

    async def restart(self):
        await self.unsubscribe()
        # Give some time for the CLOSE events to propagate before restarting
        await asyncio.sleep(10)

        logger.info("Restarting NostrClient...")
        await self.send_req_queue.put(ValueError("Restarting NostrClient..."))
        await self.recieve_event_queue.put(ValueError("Restarting NostrClient..."))

        self.ws.close()
        self.ws = None

    async def stop(self):
        await self.unsubscribe()

        # Give some time for the CLOSE events to propagate before closing the connection
        await asyncio.sleep(10)
        self.ws.close()
        self.ws = None

    async def unsubscribe(self, subscription_id):
        await self.send_req_queue.put(["CLOSE", subscription_id])
        logger.debug(f"Unsubscribed from subscription id: {subscription_id}")


class NostrWalletConnectWallet(Wallet):
    def __init__(self):
        from lnbits.app import settings
        from lnbits.tasks import catch_everything_and_restart

        self.tasks = []

        self.get_payment_status_response_event = asyncio.Event()
        self.pay_invoice_response_event = asyncio.Event()
        self.create_invoice_response_event = asyncio.Event()
        self.list_invoices_response_event = asyncio.Event()
        self.get_balance_response_event = asyncio.Event()

        self.response_data = None
        self.nostr_client = NostrClient()

        self.secret = settings.nostr_wallet_connect_secret
        self.public_key = derive_public_key(self.secret)
        self.wallet_connect_service_pubkey = settings.nostr_wallet_connect_pubkey

        async def _subscribe_to_nostr_client():
            # wait for 'nostrclient' extension to initialize
            await asyncio.sleep(5)
            await self.nostr_client.run_forever()
            await self.nostr_client.connected_event.wait()
            raise ValueError("Must reconnect to websocket")

        async def _wait_for_nostr_events():
            # wait for this extension to initialize
            await asyncio.sleep(5)
            await self.wait_for_nostr_events(self.nostr_client)

        loop = asyncio.get_event_loop()
        self.tasks.append(
            loop.create_task(catch_everything_and_restart(_subscribe_to_nostr_client))
        )
        self.tasks.append(
            loop.create_task(catch_everything_and_restart(_wait_for_nostr_events))
        )

    async def status(self) -> StatusResponse:
        if self.nostr_client.ws and self.nostr_client.ws.sock.connected:
            logger.debug("Getting wallet balance")
            eventdata = {
                "method": "get_balance",
                "params": {},
            }
            event = self.build_encrypted_event(
                json.dumps(eventdata),
                self.secret,
                self.wallet_connect_service_pubkey,
                EventKind.WALLET_CONNECT_REQUEST,
            )
            try:
                await asyncio.wait_for(
                    self.nostr_client.publish_nostr_event(event), timeout=5
                )
                await self.get_balance_response_event.wait()

                if self.response_data:
                    response = json.loads(self.response_data)
                    logger.debug("Response: get_balance")
                    if response["result_type"] == "get_balance":
                        self.create_invoice_response_event.clear()
                        logger.debug(f"Response: {response}")
                        balance = response["result"]["balance"]
                        return StatusResponse(None, balance)
                else:
                    return StatusResponse("No balance received", 0)
            except Exception as ex:
                logger.error(ex)
                return StatusResponse("Exception getting balance", 0)

        return StatusResponse(None, 0)

    async def cleanup(self):
        for task in self.tasks:
            task.cancel()

            try:
                await task
            except asyncio.CancelledError:
                print("Task was cancelled")

    async def create_invoice(
        self,
        amount: int,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
        **kwargs,
    ) -> InvoiceResponse:
        logger.debug("Create an invoice")
        eventdata = {
            "method": "make_invoice",
            "params": {
                "amount": amount * 1000,
                "memo": memo or "",
                "description_hash": description_hash.hex() if description_hash else "",
            },
        }
        event = self.build_encrypted_event(
            json.dumps(eventdata),
            self.secret,
            self.wallet_connect_service_pubkey,
            EventKind.WALLET_CONNECT_REQUEST,
        )
        try:
            await asyncio.wait_for(
                self.nostr_client.publish_nostr_event(event), timeout=5
            )
            await self.create_invoice_response_event.wait()

            if self.response_data:
                response = json.loads(self.response_data)
                logger.debug("Response: make_invoice")
                if response["result_type"] == "make_invoice":
                    self.create_invoice_response_event.clear()
                    logger.debug(f"Response: {response}")
                    payment_hash = response["result"]["payment_hash"]
                    payment_request = response["result"]["invoice"]
                    return InvoiceResponse(True, payment_hash, payment_request, None)
            else:
                return InvoiceResponse(False, None, None, "No response received")
        except Exception as ex:
            logger.error(ex)
            return InvoiceResponse(False, None, None, f"Error: {ex}")

    async def pay_invoice(self, bolt11: str, fee_limit_msat: int) -> PaymentResponse:
        logger.debug("request pay_invoice")
        eventdata = {
            "method": "pay_invoice",
            "params": {
                "invoice": bolt11,
            },
        }
        event = self.build_encrypted_event(
            json.dumps(eventdata),
            self.secret,
            self.wallet_connect_service_pubkey,
            EventKind.WALLET_CONNECT_REQUEST,
        )
        await self.nostr_client.publish_nostr_event(event)
        await self.pay_invoice_response_event.wait()

        if self.response_data:
            response = json.loads(self.response_data)
            if response["result_type"] == "pay_invoice":
                logger.debug("Response: pay_invoice")
                self.pay_invoice_response_event.clear()
                fee_msat = None
                preimage = None
                error_message = None
                checking_id = None

                if response.get("result", {}).get("error", None):
                    error_message = (
                        f'{response["result"]["error"]["code"]}: '
                        f'{response["result"]["error"]["message"]}'
                    )
                else:
                    fee_msat = None
                    preimage = response["result"]["preimage"]
                    checking_id = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()

                return PaymentResponse(
                    ok=True,
                    checking_id=checking_id,
                    fee_msat=fee_msat,
                    preimage=preimage,
                    error_message=error_message,
                )
        else:
            return PaymentResponse(ok=False, error_message="Error. Invoice not paid.")

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        return await self.get_payment_status(checking_id)

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        logger.debug(f"Checking payment status for {checking_id}")
        eventdata = {
            "method": "lookup_invoice",
            "params": {
                "payment_hash": checking_id,
            },
        }
        event = self.build_encrypted_event(
            json.dumps(eventdata),
            self.secret,
            self.wallet_connect_service_pubkey,
            EventKind.WALLET_CONNECT_REQUEST,
        )
        await self.nostr_client.publish_nostr_event(event)
        await self.get_payment_status_response_event.wait()

        if self.response_data:
            response = json.loads(self.response_data)
            logger.debug("Response: get_payment_status")
            logger.debug(response)
            if response["result_type"] == "lookup_invoice":
                logger.debug("Response: lookup_invoice")

                self.get_payment_status_response_event.clear()

                logger.debug(f"Response: {response}")

                if response.get("result") and response.get("result", {}).get(
                    "settled_at", None
                ):
                    fees_paid = response.get("result", {}).get("fees_paid", None)
                    preimage = response.get("result", {}).get("preimage", None)
                    return PaymentStatus(
                        paid=True, fee_msat=fees_paid, preimage=preimage
                    )
                else:
                    logger.debug("Payment not settled")
                    return PaymentStatus(paid=False)
            else:
                logger.debug("result_type not lookup_invoice")
                return PaymentStatus(paid=False)

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        sleep_time = 10
        paid_invoices_stream_start_time = int(time.time())
        while True:
            try:
                logger.debug("Getting paid invoices")
                try:
                    timeout = 5
                    paid_invoices = await asyncio.wait_for(
                        self.nwc_list_paid_invoices(paid_invoices_stream_start_time),
                        timeout,
                    )
                    paid_invoices_stream_start_time = int(time.time())
                    logger.debug(f"Paid invoices: {paid_invoices}")
                    if paid_invoices:
                        for invoice in paid_invoices:
                            yield invoice["payment_hash"]
                except asyncio.TimeoutError:
                    print(f"Timeout occurred after waiting for {timeout} seconds")
            except Exception as ex:
                logger.error(ex)
            await asyncio.sleep(sleep_time)

    async def nwc_list_paid_invoices(self, since_timestamp: int) -> List[Dict]:
        logger.info("Getting transactions list")
        eventdata = {
            "method": "list_transactions",
            "params": {"limit": 10, "unpaid": False, "type": "incoming"},
        }
        event = self.build_encrypted_event(
            json.dumps(eventdata),
            self.secret,
            self.wallet_connect_service_pubkey,
            EventKind.WALLET_CONNECT_REQUEST,
        )
        await self.nostr_client.publish_nostr_event(event)
        await self.list_invoices_response_event.wait()

        if self.response_data:
            response = json.loads(self.response_data)
            if response["result_type"] == "list_transactions":
                logger.debug("Response: list_transactions")

                self.list_invoices_response_event.clear()

                logger.debug(f"Response: {response}")

                if response.get("result") and response.get("result", {}).get(
                    "transactions", None
                ):
                    logger.debug("Transactions found")
                    return response.get("result", {}).get("transactions", [])
                else:
                    logger.debug("No transactions found")
                    return []
        else:
            logger.debug("No transactions found:")
            return []

    async def wait_for_nostr_events(self, nostr_client: NostrClient):

        await self.subscribe_to_wallet_service(nostr_client)

        while True:
            message = await nostr_client.get_event()
            await self.process_nostr_message(message)

    async def subscribe_to_wallet_service(self, nostr_client: NostrClient):
        # get env NOSTR_WALLET_CONNECT_PUBKEY value
        logger.info("Subscribing to wallet service")
        logger.debug(f"Wallet service pubkey: {settings.nostr_wallet_connect_pubkey}")
        public_keys = [settings.nostr_wallet_connect_pubkey]

        await nostr_client.subscribe_wallet_service(public_keys, [self.public_key])

    async def process_nostr_message(self, msg: str):
        try:
            event_type, *rest = json.loads(msg)

            if event_type.upper() == "EVENT":
                _, event = rest
                event = NostrEvent(**event)
                logger.debug(f"Event received: {event}")
                if event.kind == EventKind.WALLET_CONNECT_RESPONSE:
                    message = await self._handle_nip04_message(event)
                    data = json.loads(message)
                    self.response_data = message
                    logger.debug(f"Result_type: {data.get('result_type')}")
                    if data.get("result_type") == "list_transactions":
                        self.list_invoices_response_event.set()
                    elif data.get("result_type") == "make_invoice":
                        self.create_invoice_response_event.set()
                    elif data.get("result_type") == "pay_invoice":
                        self.pay_invoice_response_event.set()
                    elif data.get("result_type") == "lookup_invoice":
                        self.get_payment_status_response_event.set()
                    elif data.get("result_type") == "get_balance":
                        self.get_balance_response_event.set()
                    else:
                        logger.error(f"Unknown result type: {data.get('result_type')}")
                elif event.kind == EventKind.WALLET_CONNECT_INFO:
                    logger.debug("Received Wallet Connect Info")
                    message = await self._handle_nip04_message(event)
                    logger.debug(f"Message: {message}")
                return

        except Exception as ex:
            logger.debug(ex)

    async def _handle_nip04_message(self, event: NostrEvent):
        sender_public_key = event.pubkey
        message = self.decrypt_message(event.content, self.secret, sender_public_key)
        return message

    def sign_hash(self, private_key: str, msg_hash: bytes) -> str:
        return sign_message_hash(private_key, msg_hash)

    def decrypt_message(
        self, encrypted_message: str, private_key: str, public_key: str
    ) -> str:
        encryption_key = get_shared_secret(private_key, public_key)
        return decrypt_message(encrypted_message, encryption_key)

    def encrypt_message(
        self, clear_text_message: str, private_key: str, public_key: str
    ) -> str:
        encryption_key = get_shared_secret(private_key, public_key)
        return encrypt_message(clear_text_message, encryption_key)

    def build_encrypted_event(
        self, message: str, from_privkey: str, to_pubkey: str, event_type: EventKind
    ) -> NostrEvent:
        content = self.encrypt_message(message, from_privkey, to_pubkey)
        this_pubkey = derive_public_key(from_privkey)
        event = NostrEvent(
            pubkey=this_pubkey,
            created_at=round(time.time()),
            kind=event_type,
            tags=[["p", to_pubkey]],
            content=content,
        )
        event.id = event.event_id
        event.sig = self.sign_hash(from_privkey, bytes.fromhex(event.id))

        return event
