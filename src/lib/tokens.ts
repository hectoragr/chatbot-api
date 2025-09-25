import { ddb, TABLES, TokenDoc } from "./ddb.js";
import { GetCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";

export async function loadActiveToken(tokenStr: string): Promise<TokenDoc> {
  const db = ddb();
  const out = await db.send(new GetCommand({ TableName: TABLES.Tokens, Key: { token: tokenStr } }));
  const t = out.Item as TokenDoc | undefined;
  if (!t) throw new Error("TOKEN_NOT_FOUND");
  if (!t.isActive) throw new Error("TOKEN_INACTIVE");
  if (t.expiresAt && new Date(t.expiresAt) < new Date()) throw new Error("TOKEN_EXPIRED");
  return t;
}

export async function incrementTokenUsed(tokenStr: string, amount: number) {
  const db = ddb();
  await db.send(new UpdateCommand({
    TableName: TABLES.Tokens,
    Key: { token: tokenStr },
    UpdateExpression: "SET #u = if_not_exists(#u, :z) + :a, #upd = :now",
    ExpressionAttributeNames: { "#u": "used", "#upd": "updatedAt" },
    ExpressionAttributeValues: { ":a": amount, ":z": 0, ":now": new Date().toISOString() }
  }));
}