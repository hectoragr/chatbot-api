import { ddb, TABLES, RateLimitDoc } from "./ddb.js";
import { GetCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";


export async function loadRateLimit(key: string): Promise<RateLimitDoc> {
    const db = ddb();
    const out = await db.send(new GetCommand({ TableName: TABLES.RateLimits, Key: { key } }));
    const rl = out.Item as RateLimitDoc | undefined;
    if (!rl) throw new Error("RATE_LIMIT_NOT_FOUND");
    return rl;
}

export async function updateRateLimit(key: string, countIncrement: number, ttlSeconds: number): Promise<number> {
    const db = ddb();
    const out = await db.send(new UpdateCommand({
        TableName: TABLES.RateLimits,
        Key: { key },
        UpdateExpression: "SET #count = if_not_exists(#count, 0) + :inc, #ttl = :ttl",
        ExpressionAttributeNames: {
            "#count": "count",
            "#ttl": "ttl"
        },
        ExpressionAttributeValues: {
            ":inc": countIncrement,
            ":ttl": Math.floor(Date.now() / 1000) + ttlSeconds
        },
        ReturnValues: "ALL_NEW"
    }));

    return out.Attributes?.count as number ?? countIncrement;
}