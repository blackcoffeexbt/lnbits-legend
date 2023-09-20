from typing import AsyncGenerator

from loguru import logger

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
            "This backend does nothing, it is here just as a placeholder, you must"
            " configure an actual backend before being able to do anything useful with"
            " LNbits."
        )
        return StatusResponse(None, 0)

    async def create_invoice(self, *_, **__) -> InvoiceResponse:
        logger.info("Create an invoice")
        return InvoiceResponse(
            ok=False, error_message="VoidWallet cannot create invoices."
        )

    async def pay_invoice(self, *_, **__) -> PaymentResponse:
        return PaymentResponse(
            ok=False, error_message="VoidWallet cannot pay invoices."
        )

    async def get_invoice_status(self, *_, **__) -> PaymentStatus:
        return PaymentStatus(None)

    async def get_payment_status(self, *_, **__) -> PaymentStatus:
        return PaymentStatus(None)

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        yield ""
