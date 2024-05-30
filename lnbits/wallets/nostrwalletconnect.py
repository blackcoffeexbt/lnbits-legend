import asyncio
import hashlib
import json

import time
from asyncio import Queue
from threading import Thread

from websocket import WebSocketApp
from pydantic import BaseModel
from secp256k1 import PublicKey

from typing import AsyncGenerator, Dict, Optional, List, Callable

from loguru import logger

from lnbits.settings import settings
from lnbits.helpers import urlsafe_short_hash

from lnbits.nostrhelpers import (
    decrypt_message,
    encrypt_message,
    get_shared_secret,
    sign_message_hash,
    derive_public_key
)

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
        id = hashlib.sha256(data.encode()).hexdigest()
        return id

    def check_signature(self):
        event_id = self.event_id
        if self.id != event_id:
            raise ValueError(
                f"Invalid event id. Expected: '{event_id}' got '{self.id}'"
            )
        try:
            pub_key = PublicKey(bytes.fromhex("02" + self.pubkey), True)
        except Exception:
            raise ValueError(
                f"Invalid public key: '{self.pubkey}' for event '{self.id}'"
            )

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

    async def connect_to_nostrclient_ws(
            self, on_open: Callable, on_message: Callable
    ) -> WebSocketApp:
        def on_error(_, error):
            logger.warning(error)

        logger.info(f"Subscribing to websockets for nostrclient extension")
        ws = WebSocketApp(
            f"wss://relay.getalby.com/v1",
            # f"ws://localhost:{settings.port}/nostrclient/api/v1/relay",
            on_message=on_message,
            on_open=on_open,
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
                req = await self.send_req_queue.get()

                if isinstance(req, ValueError):
                    running = False
                    logger.warning(str(req))
                else:
                    logger.info(f"Sending request: {req}")
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
    ):
        dm_time = int(time.time())
        dm_filters = self._filters_for_nostr_wallet_connect_messages(public_keys, dm_time)

        self.subscription_id = "nostrwalletconnect-" + urlsafe_short_hash()[:32]
        await self.send_req_queue.put(["REQ", self.subscription_id] + dm_filters)
        # log dm_filters
        logger.debug(dm_filters)

        logger.info(
            f"Subscribed to events for: {len(public_keys)} keys. New subscription id: {self.subscription_id}"
        )

    async def subscribe_merchants(
            self,
            public_keys: List[str],
            dm_time=0,
            stall_time=0,
            product_time=0,
            profile_time=0,
    ):
        dm_filters = self._filters_for_direct_messages(public_keys, dm_time)
        stall_filters = self._filters_for_stall_events(public_keys, stall_time)
        product_filters = self._filters_for_product_events(public_keys, product_time)
        profile_filters = self._filters_for_user_profile(public_keys, profile_time)

        merchant_filters = (
                dm_filters + stall_filters + product_filters + profile_filters
        )

        self.subscription_id = "nostrmarket-" + urlsafe_short_hash()[:32]
        await self.send_req_queue.put(["REQ", self.subscription_id] + merchant_filters)

        logger.debug(
            f"Subscribed to events for: {len(public_keys)} keys. New subscription id: {self.subscription_id}"
        )

    async def merchant_temp_subscription(self, pk, duration=10):
        dm_filters = self._filters_for_direct_messages([pk], 0)
        stall_filters = self._filters_for_stall_events([pk], 0)
        product_filters = self._filters_for_product_events([pk], 0)
        profile_filters = self._filters_for_user_profile([pk], 0)

        merchant_filters = (
                dm_filters + stall_filters + product_filters + profile_filters
        )

        subscription_id = "merchant-" + urlsafe_short_hash()[:32]
        logger.debug(
            f"New merchant temp subscription ({duration} sec). Subscription id: {subscription_id}"
        )
        await self.send_req_queue.put(["REQ", subscription_id] + merchant_filters)

        async def unsubscribe_with_delay(sub_id, d):
            await asyncio.sleep(d)
            await self.unsubscribe(sub_id)

        asyncio.create_task(unsubscribe_with_delay(subscription_id, duration))

    async def user_profile_temp_subscribe(self, public_key: str, duration=5) -> List:
        try:
            profile_filter = [{"kinds": [0], "authors": [public_key]}]
            subscription_id = "profile-" + urlsafe_short_hash()[:32]
            logger.debug(
                f"New user temp subscription ({duration} sec). Subscription id: {subscription_id}"
            )
            await self.send_req_queue.put(["REQ", subscription_id] + profile_filter)

            async def unsubscribe_with_delay(sub_id, d):
                await asyncio.sleep(d)
                await self.unsubscribe(sub_id)

            asyncio.create_task(unsubscribe_with_delay(subscription_id, duration))
        except Exception as ex:
            logger.debug(ex)

    def _filters_for_direct_messages(self, public_keys: List[str], since: int) -> List:
        out_messages_filter = {"kinds": [4], "authors": public_keys}
        if since and since != 0:
            out_messages_filter["since"] = since

        return [out_messages_filter]

    def _filters_for_nostr_wallet_connect_messages(self, public_keys: List[str], since: int) -> List:
        out_messages_filter = {"kinds": [EventKind.WALLET_CONNECT_INFO, EventKind.WALLET_CONNECT_REQUEST,
                                         EventKind.WALLET_CONNECT_RESPONSE], "authors": public_keys}
        if since and since != 0:
            out_messages_filter["since"] = since

        return [out_messages_filter]

    async def restart(self):
        await self.unsubscribe_merchants()
        # Give some time for the CLOSE events to propagate before restarting
        await asyncio.sleep(10)

        logger.info("Restating NostrClient...")
        await self.send_req_queue.put(ValueError("Restarting NostrClient..."))
        await self.recieve_event_queue.put(ValueError("Restarting NostrClient..."))

        self.ws.close()
        self.ws = None

    async def stop(self):
        await self.unsubscribe_merchants()

        # Give some time for the CLOSE events to propagate before closing the connection
        await asyncio.sleep(10)
        self.ws.close()
        self.ws = None

    async def unsubscribe_merchants(self):
        await self.send_req_queue.put(["CLOSE", self.subscription_id])
        logger.debug(
            f"Unsubscribed from all merchants events. Subscription id: {self.subscription_id}"
        )

    async def unsubscribe(self, subscription_id):
        await self.send_req_queue.put(["CLOSE", subscription_id])
        logger.debug(f"Unsubscribed from subscription id: {subscription_id}")


class NostrWalletConnectWallet(Wallet):
    def __init__(self):
        from lnbits.tasks import catch_everything_and_restart
        from lnbits.app import settings

        self.response_event = asyncio.Event()
        self.response_data = None
        self.nostr_client = NostrClient()

        scheduled_tasks: List[Task] = []

        self.secret = settings.nostr_wallet_connect_secret
        self.wallet_connect_service_pubkey = settings.nostr_wallet_connect_pubkey

        async def _subscribe_to_nostr_client():
            # wait for 'nostrclient' extension to initialize
            await asyncio.sleep(10)
            await self.nostr_client.run_forever()
            raise ValueError("Must reconnect to websocket")

        async def _wait_for_nostr_events():
            # wait for this extension to initialize
            await asyncio.sleep(15)
            await self.wait_for_nostr_events(self.nostr_client)

        loop = asyncio.get_event_loop()
        task1 = loop.create_task(catch_everything_and_restart(_subscribe_to_nostr_client))
        task2 = loop.create_task(catch_everything_and_restart(_wait_for_nostr_events))
        scheduled_tasks.extend([task1, task2])

    async def status(self) -> StatusResponse:
        logger.warning(
            "This NostrWalletConnectWallet backend does nothing, it is here just as a placeholder, you must"
            " configure an actual backend before being able to do anything useful with"
            " LNbits."
        )
        return StatusResponse(None, 0)

    async def create_invoice(
            self,
            amount: int,
            memo: Optional[str] = None,
            description_hash: Optional[bytes] = None,
            unhashed_description: Optional[bytes] = None,
            **kwargs,
    ) -> InvoiceResponse:
        logger.info("Create an invoice")
        eventdata = {
            "method": "make_invoice",
            "params": {
                "amount": amount,
                "memo": memo or "",
                "description_hash": description_hash.hex() if description_hash else "",
            }
        }
        event = self.build_encrypted_event(json.dumps(eventdata), self.secret, self.wallet_connect_service_pubkey,
                                           EventKind.WALLET_CONNECT_REQUEST)
        await self.nostr_client.publish_nostr_event(event)
        await self.response_event.wait()

        if self.response_data:
            response = json.loads(self.response_data)
            logger.info(f"Response: {response}")
            if response["result_type"] == "make_invoice":
                self.response_event.clear()
                return InvoiceResponse(
                    True, response['result']['payment_hash'], response['result']['invoice'], None
                )
        else:
            return InvoiceResponse(False, None, None, "No response received")

    async def pay_invoice(self, bolt11: str, fee_limit_msat: int) -> PaymentResponse:
        logger.info("Create an invoice")
        eventdata = {
            "method": "pay_invoice",
            "params": {
                "invoice": bolt11,
            }
        }
        event = self.build_encrypted_event(json.dumps(eventdata), self.secret, self.wallet_connect_service_pubkey,
                                           EventKind.WALLET_CONNECT_REQUEST)
        await self.nostr_client.publish_nostr_event(event)
        # 3. await for response from funding source: Use asyncio Events for this probably??
        # TODO: Insert await event here
        # 4. decode response and show invoice
        #  TODO: this data Dict will be constructed using the response from the wallet service

        return PaymentResponse(
            ok=False, error_message="NostrWalletConnectWallet cannot pay invoices."
        )

    async def get_invoice_status(self, *_, **__) -> PaymentStatus:
        return PaymentStatus(None)

    async def get_payment_status(self, *_, **__) -> PaymentStatus:
        return PaymentStatus(None)

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        yield ""

    async def stub_receive_specific_message(self, uri, target_message):
        async with websockets.connect(uri) as websocket:
            while True:
                message = await websocket.recv()
                # remove whitespace and newlines
                message = message.strip()
                if message == target_message:
                    print(f"Received target message: {message}")
                    return message
                else:
                    print(f"Received another message: {message}")

    async def wait_for_nostr_events(self, nostr_client: NostrClient):

        await self.subscribe_to_wallet_service(nostr_client)

        while True:
            message = await nostr_client.get_event()
            logger.info(f"Received message: {message}")
            await self.process_nostr_message(message)

    async def subscribe_to_wallet_service(self, nostr_client: NostrClient):
        # get env NOSTR_WALLET_CONNECT_PUBKEY value
        logger.info("Subscribing to wallet service")
        logger.info(f"Wallet service pubkey: {settings.nostr_wallet_connect_pubkey}")
        public_keys = [settings.nostr_wallet_connect_pubkey]

        await nostr_client.subscribe_wallet_service(public_keys)

    async def process_nostr_message(self, msg: str):

        try:
            type, *rest = json.loads(msg)
            logger.info(f"Type: {type}")
            logger.info(f"Rest: {rest}")

            if type.upper() == "EVENT":
                _, event = rest
                logger.info(f"Event: {event}")
                event = NostrEvent(**event)
                if event.kind == 4:
                    logger.info(f"Received DM: {event.content}")
                    await self._handle_nip04_message(event)
                elif event.kind == EventKind.WALLET_CONNECT_RESPONSE:
                    logger.info(f"Received Wallet Connect Response: {event.content}")
                    message = await self._handle_nip04_message(event)
                    self.response_data = message
                    self.response_event.set()
                return

        except Exception as ex:
            logger.debug(ex)

    async def _handle_nip04_message(self, event: NostrEvent):
        sender_public_key = event.pubkey
        message = self.decrypt_message(event.content, self.secret, sender_public_key)
        return message

    def sign_hash(self, private_key: str, hash: bytes) -> str:
        return sign_message_hash(private_key, hash)

    def decrypt_message(self, encrypted_message: str, private_key: str, public_key: str) -> str:
        encryption_key = get_shared_secret(private_key, public_key)
        return decrypt_message(encrypted_message, encryption_key)

    def encrypt_message(self, clear_text_message: str, private_key: str, public_key: str) -> str:
        encryption_key = get_shared_secret(private_key, public_key)
        return encrypt_message(clear_text_message, encryption_key)

    def build_encrypted_event(self, message: str, from_privkey: str, to_pubkey: str,
                              event_type: EventKind) -> NostrEvent:
        content = self.encrypt_message(message, from_privkey, to_pubkey)
        this_pubkey = derive_public_key(from_privkey)
        logger.info(f"this_pubkey: {this_pubkey}")
        event = NostrEvent(
            pubkey=this_pubkey,
            created_at=round(time.time()),
            kind=event_type,
            tags=[["p", to_pubkey]],
            content=content,
        )
        event.id = event.event_id
        logger.info(f"event.id: {event.id}")
        event.sig = self.sign_hash(from_privkey, bytes.fromhex(event.id))

        return event
