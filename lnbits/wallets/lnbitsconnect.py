from typing import AsyncGenerator, Dict, Optional

import websockets
from loguru import logger

from lnbits.settings import settings

from .base import (
    InvoiceResponse,
    PaymentResponse,
    PaymentStatus,
    StatusResponse,
    Wallet,
)


class LNbitsConnectWallet(Wallet):
    def __init__(self):
        self.nsec = settings.lnbits_connect_nsec
        self.funding_source_npub = settings.lnbits_connect_npub
        # if not endpoint or not key:
        #     raise Exception("cannot initialize lntxbod")
        # self.endpoint = endpoint[:-1] if endpoint.endswith("/") else endpoint
        # self.auth = {"Authorization": f"Basic {key}"}
        # self.client = httpx.AsyncClient(base_url=self.endpoint, headers=self.auth)

    # async def cleanup(self):
    # try:
    #     await self.client.aclose()
    # except RuntimeError as e:
    #     logger.warning(f"Error closing wallet connection: {e}")

    async def status(self) -> StatusResponse:
        logger.warning(
            "This LNbitsConnectWallet backend does nothing, it is here just as a placeholder, you must"
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
        # Steps:
        # 1. create nostr event with type = create_invoice, funding source npub and amount
        # 2. broadcast event
        # 3. wait for response from funding source
        # 4. decode response and

        await self.stub_receive_specific_message(
            "ws://localhost:8080", "INVOICE_CREATED"
        )

        data: Dict = {"amount": amount, "description_hash": "", "memo": memo or ""}
        if description_hash:
            data["description_hash"] = description_hash.hex()
        elif unhashed_description:
            data["description_hash"] = hashlib.sha256(unhashed_description).hexdigest()

        data[
            "payment_hash"
        ] = "c1c9721247a875ba60aa534b992b42c5a3da81e66537af435ee8835bd0eb97dc"
        data[
            "payment_request"
        ] = "lnbc100n1pjskg4fsp5vpgpp83awjhs5asa3fl0hhezm30ftzwzywvq6m7za7jwfg32l27qpp5c8yhyyj84p6m5c922d9ej26zck3a4q0xv5m67s67azp4h58tjlwqdq2f38xy6t5wvxqzjccqpjrzjq2e0f6yh2eyluj4vmmz2gh205z8u5hn0gv69kcpvegpcum2dznl95zlteuqq92gqqyqqqqqqqqqqq7qqjq9qxpqysgqd46ug2c7dcdf6pglyuj4s2dfuxv8y5hxgadscftkw49vqwlxrv8s36ay746c52gqnrd276ch9pf8acuw5duj34v0n0z6wwyer052hhsqv36rn8"

        return InvoiceResponse(
            True, data["payment_hash"], data["payment_request"], None
        )
        # return InvoiceResponse(
        #     ok=False, error_message="LNbitsConnectWallet cannot create invoices."
        # )

    async def pay_invoice(self, *_, **__) -> PaymentResponse:
        return PaymentResponse(
            ok=False, error_message="LNbitsConnectWallet cannot pay invoices."
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
