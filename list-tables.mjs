import { DynamoDBClient, ListTablesCommand } from "@aws-sdk/client-dynamodb";

const client = new DynamoDBClient({
  region: "us-east-1", 
  endpoint: "http://localhost:8000",
  credentials: { 
    accessKeyId: "local", 
    secretAccessKey: "local" 
  }
});

try {
  const result = await client.send(new ListTablesCommand({}));
  console.log("Existing tables:", result.TableNames || []);
} catch (error) {
  console.error("Error listing tables:", error.message);
}
