import { DynamoDBClient, DeleteTableCommand, CreateTableCommand } from "@aws-sdk/client-dynamodb";

const REGION = process.env.AWS_REGION || "us-east-1";
const ENDPOINT = process.env.DDB_ENDPOINT;
const LOCAL = process.env.LOCAL_DDB === "true";

const client = new DynamoDBClient({ 
  region: REGION, 
  ...(LOCAL && ENDPOINT ? { 
    endpoint: ENDPOINT, 
    credentials: { accessKeyId: "local", secretAccessKey: "local" } 
  } : {}) 
});

const CONVERSATIONS_TABLE = process.env.DDB_CONVERSATIONS || "Conversations";

async function deleteConversationsTable() {
  try {
    await client.send(new DeleteTableCommand({ TableName: CONVERSATIONS_TABLE }));
    console.log(`🗑️ Deleted table: ${CONVERSATIONS_TABLE}`);
  } catch (err) {
    if (err.name !== 'ResourceNotFoundException') {
      throw err;
    }
  }
}

async function createConversationsTable() {
  await client.send(new CreateTableCommand({
    TableName: CONVERSATIONS_TABLE,
    AttributeDefinitions: [
      { AttributeName: "conversation_id", AttributeType: "S" },
      { AttributeName: "token_user", AttributeType: "S" },
      { AttributeName: "createdAt", AttributeType: "S" }
    ],
    KeySchema: [
      { AttributeName: "conversation_id", KeyType: "HASH" }
    ],
    GlobalSecondaryIndexes: [
      {
        IndexName: "byTokenUserCreatedAt",
        KeySchema: [
          { AttributeName: "token_user", KeyType: "HASH" },
          { AttributeName: "createdAt", KeyType: "RANGE" }
        ],
        Projection: { ProjectionType: "ALL" },
        ProvisionedThroughput: { ReadCapacityUnits: 1, WriteCapacityUnits: 1 }
      }
    ],
    ProvisionedThroughput: { ReadCapacityUnits: 1, WriteCapacityUnits: 1 }
  }));
  console.log(`➕ Created table: ${CONVERSATIONS_TABLE}`);
}

async function main() {
  await deleteConversationsTable();
  await createConversationsTable();
}

main().catch(console.error);
