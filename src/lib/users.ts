import { ddb, TABLES, UserDoc } from "./ddb.js";
import { GetCommand, PutCommand, DeleteCommand, ScanCommand } from "@aws-sdk/lib-dynamodb";

export async function createUserIfNotExists(user_id: string, name: string, email: string, company: string = ''): Promise<boolean> {
    const db = ddb();
    const now = new Date().toISOString();
    try {
      await db.send(new PutCommand({
        TableName: TABLES.Users,
        Item: {
          user_id,
          name,
          email,
          company,
          createdAt: now,
          updatedAt: now
        },
        ConditionExpression: "attribute_not_exists(user_id)"
      }));
      return true; // User created
    } catch (e) {
      return false; // User already exists or error
    }
}

export async function updateUser(user_id: string, name?: string, email?: string, company?: string): Promise<UserDoc | null> {
  const db = ddb();
  const existing = await getUserById(user_id);
  if (!existing) return null;
  const updatedUser: UserDoc = {
    ...existing,
    name: name || existing.name,
    email: email || existing.email,
    company: company || existing.company,
    updatedAt: new Date().toISOString()
  };
  await db.send(new PutCommand({
    TableName: TABLES.Users,
    Item: updatedUser
  }));
  return updatedUser;
}

export async function getUserById(user_id: string): Promise<UserDoc | null> {
    if (!user_id) return null;
    try {
        const db = ddb();
        const out = await db.send(new GetCommand({ TableName: TABLES.Users, Key: { user_id } }));
        return out.Item as UserDoc | null;
    } catch (e) {
        console.error(e);
        return null;
    }
}

export async function deleteUserById(user_id: string): Promise<boolean> {
  const db = ddb();
  try {
    await db.send(new DeleteCommand({ TableName: TABLES.Users, Key: { user_id } }));
    return true;
  } catch (e) {
    return false;
  }
}

export async function listUsers(limit: number = 100): Promise<UserDoc[]> {
  const db = ddb();
  const out = await db.send(new ScanCommand({ TableName: TABLES.Users, Limit: limit }));
  return (out.Items as UserDoc[]) || [];
}