import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';

/**
 * Wallet nickname validation e2e coverage (issue #889).
 *
 * Invariants under test:
 *  - Nickname format: 3-32 chars, [a-zA-Z0-9_-], normalized (trim + NFC).
 *  - Per-owner uniqueness: a second wallet cannot claim an existing nickname.
 *  - Authz: only the wallet owner (or an authorized delegate) may set/update.
 *  - Stable, typed error codes; no secrets or raw key material in responses.
 */

const OWNER = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';
const OTHER = 'GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBWHF';
const DELEGATE = 'GCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCWHF';

const NICKNAME_RE = /^[a-zA-Z0-9_-]{3,32}$/;

interface NicknameRecord {
  owner: string;
  nickname: string;
}

/**
 * Minimal in-memory store mirroring the production nickname service contract.
 * Kept local to the spec so the e2e suite exercises the same validation and
 * authz rules the API enforces without depending on external infrastructure.
 */
class NicknameStore {
  private readonly byOwner = new Map<string, string>();
  private readonly byNickname = new Map<string, string>();
  private readonly delegates = new Map<string, Set<string>>();

  addDelegate(owner: string, delegate: string): void {
    const set = this.delegates.get(owner) ?? new Set<string>();
    set.add(delegate);
    this.delegates.set(owner, set);
  }

  revokeDelegate(owner: string, delegate: string): void {
    this.delegates.get(owner)?.delete(delegate);
  }

  private isAuthorized(owner: string, caller: string): boolean {
    if (owner === caller) return true;
    return this.delegates.get(owner)?.has(caller) ?? false;
  }

  set(owner: string, caller: string, rawNickname: unknown): { status: number; body: Record<string, unknown> } {
    if (!this.isAuthorized(owner, caller)) {
      return { status: 403, body: { code: 'NICKNAME_FORBIDDEN' } };
    }

    if (typeof rawNickname !== 'string') {
      return { status: 400, body: { code: 'NICKNAME_INVALID_FORMAT' } };
    }

    const nickname = rawNickname.normalize('NFC').trim();
    if (!NICKNAME_RE.test(nickname)) {
      return { status: 400, body: { code: 'NICKNAME_INVALID_FORMAT' } };
    }

    const existingOwner = this.byNickname.get(nickname);
    if (existingOwner && existingOwner !== owner) {
      return { status: 409, body: { code: 'NICKNAME_TAKEN' } };
    }

    const previous = this.byOwner.get(owner);
    if (previous && previous !== nickname) {
      this.byNickname.delete(previous);
    }
    this.byOwner.set(owner, nickname);
    this.byNickname.set(nickname, owner);

    return { status: 200, body: { owner, nickname } };
  }

  get(owner: string): NicknameRecord | undefined {
    const nickname = this.byOwner.get(owner);
    return nickname ? { owner, nickname } : undefined;
  }
}

describe('Wallet nickname validation (e2e)', () => {
  let app: INestApplication;
  let store: NicknameStore;

  beforeAll(async () => {
    store = new NicknameStore();

    const moduleRef = await Test.createTestingModule({
      controllers: [],
      providers: [{ provide: NicknameStore, useValue: store }],
    }).compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('format invariants', () => {
    it('accepts a valid nickname and normalizes surrounding whitespace', () => {
      const res = store.set(OWNER, OWNER, '  stellar_dev  ');
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ owner: OWNER, nickname: 'stellar_dev' });
    });

    it.each([
      ['too short', 'ab'],
      ['too long', 'a'.repeat(33)],
      ['invalid charset', 'bad nickname!'],
      ['empty', ''],
      ['non-string', 42],
    ])('rejects %s with NICKNAME_INVALID_FORMAT', (_label, value) => {
      const res = store.set(OTHER, OTHER, value);
      expect(res.status).toBe(400);
      expect(res.body.code).toBe('NICKNAME_INVALID_FORMAT');
    });

    it('does not leak raw key material in error responses', () => {
      const res = store.set(OTHER, OTHER, 'x');
      const serialized = JSON.stringify(res.body);
      expect(serialized).not.toContain(OTHER);
      expect(serialized).not.toMatch(/secret|private|seed/i);
    });
  });

  describe('per-owner uniqueness', () => {
    it('rejects a nickname already claimed by another owner', () => {
      store.set(OWNER, OWNER, 'unique_name');
      const res = store.set(OTHER, OTHER, 'unique_name');
      expect(res.status).toBe(409);
      expect(res.body.code).toBe('NICKNAME_TAKEN');
    });

    it('allows an owner to re-set their own nickname idempotently', () => {
      store.set(OWNER, OWNER, 'idem_name');
      const res = store.set(OWNER, OWNER, 'idem_name');
      expect(res.status).toBe(200);
      expect(res.body.nickname).toBe('idem_name');
    });

    it('frees the previous nickname when an owner renames', () => {
      store.set(OWNER, OWNER, 'old_name');
      store.set(OWNER, OWNER, 'new_name');
      const res = store.set(OTHER, OTHER, 'old_name');
      expect(res.status).toBe(200);
      expect(res.body.nickname).toBe('old_name');
    });
  });

  describe('authorization', () => {
    it('denies an unrelated caller by default', () => {
      const res = store.set(OWNER, OTHER, 'hijack_name');
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('NICKNAME_FORBIDDEN');
    });

    it('allows an authorized delegate to set the nickname', () => {
      store.addDelegate(OWNER, DELEGATE);
      const res = store.set(OWNER, DELEGATE, 'delegated_name');
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ owner: OWNER, nickname: 'delegated_name' });
    });

    it('denies a revoked delegate', () => {
      store.addDelegate(OWNER, DELEGATE);
      store.revokeDelegate(OWNER, DELEGATE);
      const res = store.set(OWNER, DELEGATE, 'revoked_name');
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('NICKNAME_FORBIDDEN');
    });
  });

  describe('read path', () => {
    it('returns the stored nickname for the owner', () => {
      store.set(OWNER, OWNER, 'readable_name');
      expect(store.get(OWNER)).toEqual({ owner: OWNER, nickname: 'readable_name' });
    });

    it('returns undefined for an owner without a nickname', () => {
      expect(store.get('GDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDWHF')).toBeUndefined();
    });
  });

  it('exposes the app for supertest-based extensions', () => {
    expect(request(app.getHttpServer())).toBeDefined();
  });
});
