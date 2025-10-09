import { DynamoDBClient, CreateTableCommand, DeleteTableCommand, ListTablesCommand, UpdateTableCommand } from "@aws-sdk/client-dynamodb";

const REGION = process.env.AWS_REGION || "us-east-1";
const ENDPOINT = process.env.DDB_ENDPOINT; // used when LOCAL_DDB=true
const LOCAL = process.env.LOCAL_DDB === "true";

const clientConfig = {
  region: REGION
};

if (LOCAL && ENDPOINT) {
  // Local development configuration
  clientConfig.endpoint = ENDPOINT;
  clientConfig.credentials = {
    accessKeyId: "local",
    secretAccessKey: "local"
  };
} else {
  // Production configuration
  if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
    clientConfig.credentials = {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    };
  }
}

const client = new DynamoDBClient(clientConfig);

const Tables = {
  Tokens: process.env.DDB_TOKENS || "Tokens",
  Users: process.env.DDB_USERS || "Users", 
  Conversations: process.env.DDB_CONVERSATIONS || "Conversations",
  TokenRequests: process.env.DDB_TOKEN_REQUESTS || "TokenRequests",
  RateLimits: process.env.DDB_RATELIMITS || "RateLimits"
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
  for (const name of [Tables.Tokens, Tables.Users, Tables.Conversations, Tables.TokenRequests, Tables.RateLimits]) {
    if (existing.TableNames?.includes(name)) {
      await client.send(new DeleteTableCommand({ TableName: name }));
      console.log(`🗑️ Deleted: ${name}`);
    }
  }
}

async function createTables() {
  const existing = await client.send(new ListTablesCommand({}));

  // Conversations table with GSIs
  if (!existing.TableNames?.includes(Tables.Conversations)) {
    await client.send(new CreateTableCommand({
      TableName: Tables.Conversations,
      KeySchema: [
        { AttributeName: "conversation_id", KeyType: "HASH" }
      ],
      AttributeDefinitions: [
        { AttributeName: "conversation_id", AttributeType: "S" },
        { AttributeName: "user_id", AttributeType: "S" },
        { AttributeName: "token_user", AttributeType: "S" },
        { AttributeName: "createdAt", AttributeType: "S" }
      ],
      GlobalSecondaryIndexes: [
        {
          IndexName: "byUserCreatedAt",
          KeySchema: [
            { AttributeName: "user_id", KeyType: "HASH" },
            { AttributeName: "createdAt", KeyType: "RANGE" }
          ],
          Projection: { ProjectionType: "ALL" }
        },
        {
          IndexName: "byTokenUserCreatedAt",
          KeySchema: [
            { AttributeName: "token_user", KeyType: "HASH" },
            { AttributeName: "createdAt", KeyType: "RANGE" }
          ],
          Projection: { ProjectionType: "ALL" }
        }
      ],
      BillingMode: "PAY_PER_REQUEST"
    }));
    console.log(`➕ Created: ${Tables.Conversations}`);
  } else {
    console.log(`✅ Table exists: ${Tables.Conversations}`);
  }

  // Tokens table
  if (!existing.TableNames?.includes(Tables.Tokens)) {
    await client.send(new CreateTableCommand({
      TableName: Tables.Tokens,
      KeySchema: [
        { AttributeName: "token", KeyType: "HASH" }
      ],
      AttributeDefinitions: [
        { AttributeName: "token", AttributeType: "S" }
      ],
      BillingMode: "PAY_PER_REQUEST"
    }));
    console.log(`➕ Created: ${Tables.Tokens}`);
  } else {
    console.log(`✅ Table exists: ${Tables.Tokens}`);
  }

  // Users table
  if (!existing.TableNames?.includes(Tables.Users)) {
    await client.send(new CreateTableCommand({
      TableName: Tables.Users,
      KeySchema: [
        { AttributeName: "user_id", KeyType: "HASH" }
      ],
      AttributeDefinitions: [
        { AttributeName: "user_id", AttributeType: "S" }
      ],
      BillingMode: "PAY_PER_REQUEST"
    }));
    console.log(`➕ Created: ${Tables.Users}`);
  } else {
    console.log(`✅ Table exists: ${Tables.Users}`);
  }

  // TokenRequests table
  if (!existing.TableNames?.includes(Tables.TokenRequests)) {
    await client.send(new CreateTableCommand({
      TableName: Tables.TokenRequests,
      KeySchema: [
        { AttributeName: "token", KeyType: "HASH" }
      ],
      AttributeDefinitions: [
        { AttributeName: "token", AttributeType: "S" }
      ],
      BillingMode: "PAY_PER_REQUEST"
    }));
    console.log(`➕ Created: ${Tables.TokenRequests}`);
  } else {
    console.log(`✅ Table exists: ${Tables.TokenRequests}`);
  }

  // RateLimits table
  if (!existing.TableNames?.includes(Tables.RateLimits)) {
    await client.send(new CreateTableCommand({
      TableName: Tables.RateLimits,
      KeySchema: [
        { AttributeName: "key", KeyType: "HASH" }
      ],
      AttributeDefinitions: [
        { AttributeName: "key", AttributeType: "S" }
      ],
      TimeToLiveSpecification: {
        AttributeName: "ttl",
        Enabled: true
      },
      BillingMode: "PAY_PER_REQUEST"
    }));
    console.log(`➕ Created: ${Tables.RateLimits}`);
  } else {
    console.log(`✅ Table exists: ${Tables.RateLimits}`);
  }
}

async function main() {
  const args = new Set(process.argv.slice(2));
  if (args.has("--purge")) {
    if (!args.has("--yes")) { console.error("Refusing to purge without --yes"); process.exit(2); }
    await purgeAll();
  }

  await createTables();

  console.log("✅ Bootstrap complete");
}

main().catch(e => { console.error(e); process.exit(1); });