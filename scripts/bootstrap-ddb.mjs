import { DynamoDBClient, CreateTableCommand, DeleteTableCommand, ListTablesCommand, UpdateTableCommand } from "@aws-sdk/client-dynamodb";

const REGION = process.env.AWS_REGION || "us-east-1";
const ENDPOINT = process.env.DDB_ENDPOINT; // used when LOCAL_DDB=true
const LOCAL = process.env.LOCAL_DDB === "true";

const client = new DynamoDBClient({ region: REGION, ...(LOCAL && ENDPOINT ? { endpoint: ENDPOINT, credentials: { accessKeyId: "local", secretAccessKey: "local" } } : {}) });

const Tables = {
  Tokens: process.env.DDB_TOKENS || "Tokens",
  Users: process.env.DDB_USERS || "Users",
  Conversations: process.env.DDB_CONVERSATIONS || "Conversations",
};

async function ensureTable(params) {
  const existing = await client.send(new ListTablesCommand({}));
  if (existing.TableNames?.includes(params.TableName)) {
    console.log(`✔ Table exists: ${params.TableName}`);
    return;
  }
  await client.send(new CreateTableCommand(params));
  console.log(`➕ Created: ${params.TableName}`);
}

async function purgeAll() {
  const existing = await client.send(new ListTablesCommand({}));
  for (const name of [Tables.Tokens, Tables.Users, Tables.Conversations]) {
    if (existing.TableNames?.includes(name)) {
      await client.send(new DeleteTableCommand({ TableName: name }));
      console.log(`🗑️ Deleted: ${name}`);
    }
  }
}

async function main() {
  const args = new Set(process.argv.slice(2));
  if (args.has("--purge")) {
    if (!args.has("--yes")) { console.error("Refusing to purge without --yes"); process.exit(2); }
    await purgeAll();
  }

  await ensureTable({
    TableName: Tables.Tokens,
    AttributeDefinitions: [{ AttributeName: "token", AttributeType: "S" }, { AttributeName: "user_id", AttributeType: "S" }],
    KeySchema: [{ AttributeName: "token", KeyType: "HASH" }],
    BillingMode: "PAY_PER_REQUEST",
    GlobalSecondaryIndexes: [{
      IndexName: "byUser",
      KeySchema: [{ AttributeName: "user_id", KeyType: "HASH" }],
      Projection: { ProjectionType: "ALL" }
    }]
  });

  await ensureTable({
    TableName: Tables.Users,
    AttributeDefinitions: [{ AttributeName: "user_id", AttributeType: "S" }],
    KeySchema: [{ AttributeName: "user_id", KeyType: "HASH" }],
    BillingMode: "PAY_PER_REQUEST"
  });

  await ensureTable({
    TableName: Tables.Conversations,
    AttributeDefinitions: [
      { AttributeName: "conversation_id", AttributeType: "S" },
      { AttributeName: "token_user", AttributeType: "S" },
      { AttributeName: "createdAt", AttributeType: "S" }
    ],
    KeySchema: [{ AttributeName: "conversation_id", KeyType: "HASH" }],
    BillingMode: "PAY_PER_REQUEST",
    GlobalSecondaryIndexes: [{
      IndexName: "byTokenUserCreatedAt",
      KeySchema: [
        { AttributeName: "token_user", KeyType: "HASH" },
        { AttributeName: "createdAt", KeyType: "RANGE" }
      ],
      Projection: { ProjectionType: "ALL" }
    }]
  });

  console.log("✅ Bootstrap complete");
}

main().catch(e => { console.error(e); process.exit(1); });