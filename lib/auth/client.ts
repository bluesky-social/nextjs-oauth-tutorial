import {
  NodeOAuthClient,
  atprotoLoopbackClientMetadata,
} from "@atproto/oauth-client-node";
import type {
  NodeSavedSession,
  NodeSavedState,
} from "@atproto/oauth-client-node";

const globalAuth = globalThis as unknown as {
  stateStore: Map<string, NodeSavedState>;
  sessionStore: Map<string, NodeSavedSession>;
};
globalAuth.stateStore ??= new Map();
globalAuth.sessionStore ??= new Map();

let client: NodeOAuthClient | null = null;

export async function getOAuthClient(): Promise<NodeOAuthClient> {
  if (client) return client;

  client = new NodeOAuthClient({
    clientMetadata: atprotoLoopbackClientMetadata(
      `http://localhost?${new URLSearchParams([
        ["redirect_uri", "http://127.0.0.1:3000/oauth/callback"],
        ["scope", "atproto"],
      ])}`,
    ),

    stateStore: {
      async get(key: string) {
        return globalAuth.stateStore.get(key);
      },
      async set(key: string, value: NodeSavedState) {
        globalAuth.stateStore.set(key, value);
      },
      async del(key: string) {
        globalAuth.stateStore.delete(key);
      },
    },

    sessionStore: {
      async get(key: string) {
        return globalAuth.sessionStore.get(key);
      },
      async set(key: string, value: NodeSavedSession) {
        globalAuth.sessionStore.set(key, value);
      },
      async del(key: string) {
        globalAuth.sessionStore.delete(key);
      },
    },
  });

  return client;
}
