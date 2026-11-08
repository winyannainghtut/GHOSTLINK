// The dashboard's connection to its server: same-origin /api with the session cookie and the
// CSRF header, and the sign-in with the token after # in the login link.
import { SignedOut, setTransport, type Server, type Transport } from '@admin/api';
import { saveBlob } from '@shared/format';

async function request(method: string, path: string, body?: unknown): Promise<Response> {
  const response = await fetch('/api' + path, {
    method,
    credentials: 'same-origin',
    headers: { 'X-Ghostlink-Dashboard': '1', 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 401) throw new SignedOut('Your session ended. Open the login link from the server again.');
  if (!response.ok) {
    let message = 'The server refused the request';
    try {
      message = (await response.json()).error || message;
    } catch {
      /* not JSON */
    }
    throw new Error(message);
  }
  return response;
}

export const dashboardTransport: Transport = {
  async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const response = await request(method, path, body);
    return response.status === 204 ? (null as T) : ((await response.json()) as T);
  },
  async text(path: string): Promise<string> {
    return (await request('GET', path)).text();
  },
  async save(file) {
    saveBlob(new Blob([file.content], { type: file.mime }), `${file.name}.${file.extension}`);
    return null;
  },
};

// The token after # in a login link, if the address has one.
export function loginToken(): string | null {
  return new URLSearchParams(location.hash.slice(1)).get('t');
}

export async function signIn(): Promise<{ server: Server | null; error: string }> {
  setTransport(dashboardTransport);
  const token = loginToken();
  if (token) {
    history.replaceState(null, '', location.pathname);
    let response: Response;
    try {
      response = await fetch('/login', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
    } catch {
      return { server: null, error: 'Could not reach the server. Check the connection or the SSH tunnel, then open the login link again.' };
    }
    if (!response.ok) {
      let message = 'This login link is not valid.';
      try {
        message = (await response.json()).error || message;
      } catch {
        /* not JSON */
      }
      return { server: null, error: message };
    }
  }
  try {
    return { server: await dashboardTransport.call<Server>('GET', '/server'), error: '' };
  } catch {
    return { server: null, error: token ? 'Could not sign in.' : '' };
  }
}

export async function signOut(): Promise<void> {
  await fetch('/logout', { method: 'POST', credentials: 'same-origin' });
}
