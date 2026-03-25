from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel

engine = None
AsyncSessionLocal = None

def init_db(db_url: str):
    global engine, AsyncSessionLocal
    
    # create_async_engine expects e.g., sqlite+aiosqlite:///
    engine = create_async_engine(db_url, echo=False)
    
    AsyncSessionLocal = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

async def create_all_tables():
    if not engine:
        raise RuntimeError("Database not initialized. Call init_db first.")
    
    # Ensure imported models so metadata is known
    import certberus.db.models  # noqa
    
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

async def get_session() -> AsyncSession:
    if not AsyncSessionLocal:
        raise RuntimeError("Database not initialized. Call init_db first.")
    async with AsyncSessionLocal() as session:
        yield session
