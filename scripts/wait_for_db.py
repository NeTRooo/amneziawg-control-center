import asyncio
import os
import sys
import asyncpg

async def main() -> None:
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        print("DATABASE_URL is not set", file=sys.stderr)
        sys.exit(1)

    # asyncpg expects postgres:// or postgresql:// without +asyncpg
    pg_url = url.replace("postgresql+asyncpg://", "postgresql://")

    timeout = float(os.environ.get("DB_WAIT_TIMEOUT", "30"))
    deadline = asyncio.get_event_loop().time() + timeout

    last_err: Exception | None = None
    while asyncio.get_event_loop().time() < deadline:
        try:
            conn = await asyncpg.connect(pg_url)
            await conn.close()
            print("DB is ready")
            return
        except Exception as e:  # noqa: BLE001
            last_err = e
            await asyncio.sleep(1)

    print(f"DB is not ready after {timeout}s: {last_err}", file=sys.stderr)
    sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
