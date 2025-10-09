import { GetCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";
import { ddb, TABLES } from "./ddb.js";


export interface RateLimitDoc {
  key: string;
  count: number;
  ttl: number;
}

export async function loadRateLimit(key: string): Promise<RateLimitDoc> {
  try {
    const result = await ddb().send(new GetCommand({
      TableName: TABLES.RateLimits,
      Key: { key }
    }));
    
    if (result.Item) {
      return result.Item as RateLimitDoc;
    }
    
    // Return default values if no rate limit record exists
    return {
      key,
      count: 0,
      ttl: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
    };
  } catch (error) {
    console.error('Error loading rate limit:', error);
    // Return default values on error
    return {
      key,
      count: 0,
      ttl: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
    };
  }
}

export async function updateRateLimit(key: string, increment: number, windowSec: number): Promise<number> {
  const ttl = Math.floor(Date.now() / 1000) + windowSec;
  
  try {
    const result = await ddb().send(new UpdateCommand({
      TableName: TABLES.RateLimits,
      Key: { key },
      UpdateExpression: "ADD #count :increment SET #ttl = :ttl",
      ExpressionAttributeNames: {
        "#count": "count",
        "#ttl": "ttl"
      },
      ExpressionAttributeValues: {
        ":increment": increment,
        ":ttl": ttl
      },
      ReturnValues: "ALL_NEW"
    }));
    
    return result.Attributes?.count || increment;
  } catch (error) {
    console.error('Error updating rate limit:', error);
    return increment; // Return the increment as fallback
  }
}