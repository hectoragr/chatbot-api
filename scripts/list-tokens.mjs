import { DynamoDB } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";

const client = new DynamoDB({
  region: "us-east-1",
  endpoint: "http://localhost:8000",
  credentials: {
    accessKeyId: "local",
    secretAccessKey: "local"
  }
});

const ddbDoc = DynamoDBDocument.from(client);

async function listTokens() {
  const result = await ddbDoc.scan({
    TableName: "Tokens"
  });
  console.log(JSON.stringify(result.Items, null, 2));
}

listTokens().catch(console.error);
