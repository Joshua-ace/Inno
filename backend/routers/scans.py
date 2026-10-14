"""
Scan history API endpoints.
GET /api/scans          - List recent scans
GET /api/scans/{scan_id} - Get a specific scan
DELETE /api/scans/{scan_id} - Delete a scan
"""

import json
import logging
from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from models import ScanSummary, ScanListResponse, ErrorResponse

logger = logging.getLogger("daddydefender.scans")

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.get(
    "",
    response_model=ScanListResponse,
)
async def list_scans(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    scan_type: str = Query(default=None, description="Filter by 'url' or 'message'"),
):
    """Retrieve recent scan history."""
    try:
        import aiosqlite
        from database import DB_PATH

        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row

            # Count total
            count_query = "SELECT COUNT(*) FROM scans"
            count_params = []
            if scan_type:
                count_query += " WHERE scan_type = ?"
                count_params.append(scan_type)

            async with db.execute(count_query, count_params) as cursor:
                row = await cursor.fetchone()
                total = row[0] if row else 0

            # Fetch scans
            query = """
                SELECT id, scan_type, created_at, input_preview,
                       risk_score, risk_level, classification
                FROM scans
            """
            params = []
            if scan_type:
                query += " WHERE scan_type = ?"
                params.append(scan_type)
            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()

            scans = [
                ScanSummary(
                    scan_id=row["id"],
                    scan_type=row["scan_type"],
                    timestamp=row["created_at"],
                    input_preview=row["input_preview"] or "",
                    risk_score=row["risk_score"],
                    risk_level=row["risk_level"],
                    classification=row["classification"],
                )
                for row in rows
            ]

            return ScanListResponse(scans=scans, total=total)

    except Exception as e:
        logger.error(f"Failed to list scans: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Failed to retrieve scan history."},
        )


@router.get(
    "/{scan_id}",
    responses={404: {"model": ErrorResponse}},
)
async def get_scan(scan_id: str):
    """Retrieve a specific scan by ID."""
    try:
        import aiosqlite
        from database import DB_PATH

        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row

            async with db.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ) as cursor:
                row = await cursor.fetchone()

            if not row:
                return JSONResponse(
                    status_code=404,
                    content={"error": "Scan not found."},
                )

            return {
                "scan_id": row["id"],
                "scan_type": row["scan_type"],
                "timestamp": row["created_at"],
                "input_preview": row["input_preview"],
                "risk_score": row["risk_score"],
                "risk_level": row["risk_level"],
                "classification": row["classification"],
                "indicators": json.loads(row["findings"]),
                "providers": json.loads(row["provider_status"]),
                "recommendations": json.loads(row["recommendations"]),
                "ai_explanation": row["ai_explanation"],
            }

    except Exception as e:
        logger.error(f"Failed to get scan: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Failed to retrieve scan."},
        )


@router.delete(
    "/{scan_id}",
    responses={404: {"model": ErrorResponse}},
)
async def delete_scan(scan_id: str):
    """Delete a specific scan."""
    try:
        import aiosqlite
        from database import DB_PATH

        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute(
                "SELECT id FROM scans WHERE id = ?", (scan_id,)
            ) as cursor:
                if not await cursor.fetchone():
                    return JSONResponse(
                        status_code=404,
                        content={"error": "Scan not found."},
                    )

            await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            await db.commit()

        return {"status": "deleted", "scan_id": scan_id}

    except Exception as e:
        logger.error(f"Failed to delete scan: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Failed to delete scan."},
        )
