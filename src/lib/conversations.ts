import { ddb, TABLES, ConversationDoc, Message } from "./ddb.js";
import { GetCommand, PutCommand, QueryCommand, UpdateCommand, BatchWriteCommand, DeleteCommand } from "@aws-sdk/lib-dynamodb";

export async function getConversation(conversation_id: string) {
  const out = await ddb().send(new GetCommand({ TableName: TABLES.Conversations, Key: { conversation_id } }));
  return out.Item as ConversationDoc | undefined;
}

export async function getConversationsByTokenUser(token: string, user_id?: string, page?: number): Promise<ConversationDoc[]> {
  if (!user_id) return [];
  const token_user = `${token}#${user_id}`;
  const out = await ddb().send(new QueryCommand({
    TableName: TABLES.Conversations,
    IndexName: "byTokenUserCreatedAt",
    KeyConditionExpression: "token_user = :pk",
    ExpressionAttributeValues: { ":pk": token_user },
    ScanIndexForward: false // most recent first
  }));
  return (out.Items as ConversationDoc[]) || [];
}

export async function getLatestConversationByTokenUser(token: string, user_id?: string) {
  const conversations = await getConversationsByTokenUser(token, user_id);
  return conversations[0];
}

export async function ensureConversation(conversation_id: string | undefined, token: string, user_id: string, provider: "OPENAI" | "DEEPSEEK" | "ANY" = "ANY"): Promise<ConversationDoc> {
  const now = new Date().toISOString();
  if (conversation_id && conversation_id.length > 5) {
    const existing = await getConversation(conversation_id);
    if (existing) return existing;
  }
  const convo: ConversationDoc = {
    conversation_id: conversation_id && conversation_id.length > 5 ? conversation_id : crypto.randomUUID(),
    token, user_id, token_user: `${token}#${user_id}`,
    displayName: `${new Date().toLocaleString()}`,
    provider,
    createdAt: now, updatedAt: now, messages: []
  };
  await ddb().send(new PutCommand({ TableName: TABLES.Conversations, Item: convo, ConditionExpression: "attribute_not_exists(conversation_id)" }));
  return convo;
}

export async function runSmallModelForSummary(userMessage: string, assistantMessage: string): Promise<string> {
  if (!process.env.DEEPSEEK_API_KEY) return `Chat on ${new Date().toLocaleString()}`;
  try {
    const messages = [
      {
        role: "system",
        content: "You are a helpful assistant that creates concise chat titles. Respond with ONLY the title, no explanations or extra text."
      },
      {
        role: "user",
        content: `Create a concise title (2-6 words) for this chat:\nUser: ${userMessage}\nAssistant: ${assistantMessage}`
      }
    ];

    const r = await fetch("https://api.deepseek.com/v1/chat/completions", {
      method: "POST",
      headers: { 
        "Content-Type": "application/json", 
        "Authorization": `Bearer ${process.env.DEEPSEEK_API_KEY}`
      },
      body: JSON.stringify({
        model: "deepseek-chat",
        messages,
        max_tokens: 20,
        temperature: 0.3,
        top_p: 0.95
      })
    });
    
    const data = await r.json();
    
    if (data?.choices?.[0]?.message?.content) {
      const title = data.choices[0].message.content.trim();
      return title.length > 100 ? title.slice(0, 100) : title;
    }
  } catch (error: any) {
    console.error('Error generating summary title:', error);
    console.error('Error details:', error.response?.data || error.message);
  }
  return `Chat from ${new Date().toLocaleTimeString()}`;
};

export async function renameConversation(conversation_id: string, newName: string) {
  await ddb().send(new UpdateCommand({
    TableName: TABLES.Conversations,
    Key: { conversation_id },
    UpdateExpression: "SET #n = :name, #u = :now",
    ExpressionAttributeNames: { "#n": "displayName", "#u": "updatedAt" },
    ExpressionAttributeValues: { 
      ":name": newName,
      ":now": new Date().toISOString()
    }
  }));
}

const MAX_MESSAGES = 200;

async function trimConversationMessages(conversation_id: string, currentMessages: Message[], newMessages: Message[]): Promise<Message[]> {
  const allMessages = [...currentMessages, ...newMessages];
  // Keep only the most recent MAX_MESSAGES messages
  return allMessages;//.slice(-MAX_MESSAGES);
}

export async function appendMessages(conversation_id: string, msgs: Message[]) {
  // First get the current conversation to check message count
  const conversation = await getConversation(conversation_id);
  if (!conversation) throw new Error("Conversation not found");

  const currentMessages = conversation.messages || [];
  const updatedMessages = await trimConversationMessages(conversation_id, currentMessages, msgs);

  await ddb().send(new UpdateCommand({
    TableName: TABLES.Conversations,
    Key: { conversation_id },
    UpdateExpression: "SET #m = :msgs, #u = :now",
    ExpressionAttributeNames: { "#m": "messages", "#u": "updatedAt" },
    ExpressionAttributeValues: { 
      ":msgs": updatedMessages,
      ":now": new Date().toISOString()
    }
  }));
}

export async function deleteByTokenAndUser(token: string, user_id: string) {
  const token_user = `${token}#${user_id}`;
  const q = await ddb().send(new QueryCommand({
    TableName: TABLES.Conversations,
    IndexName: "byTokenUserCreatedAt",
    KeyConditionExpression: "token_user = :pk",
    ExpressionAttributeValues: { ":pk": token_user }
  }));
  const items = q.Items || [];
  for (let i = 0; i < items.length; i += 25) {
    const chunk = items.slice(i, i + 25);
    await ddb().send(new BatchWriteCommand({
      RequestItems: { [TABLES.Conversations]: chunk.map(it => ({ DeleteRequest: { Key: { conversation_id: it.conversation_id } } })) }
    }));
  }
}