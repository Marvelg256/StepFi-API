import { Test, TestingModule } from '@nestjs/testing';
import { InternalServerErrorException, ConflictException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { createHash } from 'crypto';
import { AuthService } from '../../../../src/modules/auth/auth.service';
import { SupabaseService } from '../../../../src/database/supabase.client';
import { UsersRepository } from '../../../../src/database/repositories/users.repository';
import { VerifyRequestDto } from '../../../../src/modules/auth/dto/verify-request.dto';

// Mock Stellar SDK to avoid real crypto operations in unit tests
jest.mock('stellar-sdk', () => ({
  Keypair: { fromPublicKey: jest.fn() },
  StrKey: { isValidEd25519PublicKey: jest.fn().mockReturnValue(true) },
}));

import { Keypair, StrKey } from 'stellar-sdk';

// Env values the service resolves in its constructor (matching the mocked
// ConfigService below) so challenge envelopes can be reproduced in tests.
// URL.host includes the port, so localhost:3000 is the challenge domain.
const CHALLENGE_DOMAIN = 'localhost:3000';
const CHALLENGE_URI = 'http://localhost:3000/api/v1/auth/verify';
const NETWORK_PASSPHRASE = 'Test SDF Network ; September 2015';
const CHALLENGE_STATEMENT =
  'StepFi requests that you sign this message to authenticate your wallet. ' +
  'This message does not trigger any blockchain transaction.';
const SEP_53_PREFIX = 'Stellar Signed Message:\n';

/** Reproduces the service's canonical challenge envelope serialization. */
function buildChallengeMessage(wallet: string, nonce: string, issuedAt: Date, expiresAt: Date): string {
  return JSON.stringify(
    {
      domain: CHALLENGE_DOMAIN,
      address: wallet,
      statement: CHALLENGE_STATEMENT,
      uri: CHALLENGE_URI,
      version: '1.0.0',
      nonce,
      issuedAt: issuedAt.toISOString(),
      expirationTime: expiresAt.toISOString(),
      networkPassphrase: NETWORK_PASSPHRASE,
    },
    null,
    2,
  );
}

describe('AuthService', () => {
  let service: AuthService;

  const mockInsert = jest.fn().mockResolvedValue({ error: null });
  const mockFrom = jest.fn().mockReturnValue({ insert: mockInsert });

  const mockSupabaseClient = { from: mockFrom };

  const mockSupabaseService = {
    getServiceRoleClient: jest.fn(() => mockSupabaseClient),
  };

  const mockJwtService = {
    sign: jest.fn().mockReturnValue('mock.jwt.token'),
  };

  const mockConfigService = {
    get: jest.fn(),
  };

  const mockUsersRepository = {
    findByWallet: jest.fn(),
    checkUsernameExists: jest.fn(),
    uploadAvatar: jest.fn(),
    createProfile: jest.fn(),
  };

  const validWallet = 'GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW';

  /**
   * Builds an AuthService with a ConfigService whose `get` returns the given
   * overrides on top of the default test configuration.
   */
  function createServiceWithConfig(overrides: Record<string, unknown> = {}): AuthService {
    const config = {
      get: jest.fn((key: string) => {
        if (key in overrides) {
          return overrides[key];
        }
        switch (key) {
          case 'API_URL':
            return 'http://localhost:3000';
          case 'API_PREFIX':
            return 'api/v1';
          case 'STELLAR_NETWORK_PASSPHRASE':
            return NETWORK_PASSPHRASE;
          case 'AUTH_CHALLENGE_DOMAIN':
            return undefined;
          case 'AUTH_ALLOW_LEGACY_RAW_SIGNATURES':
            return undefined; // default: legacy accepted during migration window
          case 'AUTH_LEGACY_SIGNATURES_SUNSET':
            return undefined; // default: LEGACY_RAW_SIGNATURES_SUNSET (2026-10-31)
          default:
            return 'mock-secret';
        }
      }),
    };
    return new AuthService(
      mockSupabaseService as unknown as SupabaseService,
      mockJwtService as unknown as JwtService,
      config as unknown as ConfigService,
      mockUsersRepository as unknown as UsersRepository,
    );
  }

  /** Config mock matching the constructor's expectations. */
  function configureConfigService() {
    mockConfigService.get.mockImplementation((key: string) => {
      switch (key) {
        case 'API_URL':
          return 'http://localhost:3000';
        case 'API_PREFIX':
          return 'api/v1';
        case 'STELLAR_NETWORK_PASSPHRASE':
          return NETWORK_PASSPHRASE;
        case 'AUTH_CHALLENGE_DOMAIN':
          return undefined;
        case 'AUTH_ALLOW_LEGACY_RAW_SIGNATURES':
          return undefined; // default: legacy accepted during migration window
        case 'AUTH_LEGACY_SIGNATURES_SUNSET':
          return undefined; // default: LEGACY_RAW_SIGNATURES_SUNSET (2026-10-31)
        default:
          return 'mock-secret';
      }
    });
  }

  beforeEach(async () => {
    configureConfigService();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: SupabaseService, useValue: mockSupabaseService },
        { provide: JwtService, useValue: mockJwtService },
        { provide: ConfigService, useValue: mockConfigService },
        { provide: UsersRepository, useValue: mockUsersRepository },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);

    jest.clearAllMocks();
    mockInsert.mockResolvedValue({ error: null });
    mockJwtService.sign.mockReturnValue('mock.jwt.token');
    configureConfigService();
    mockFrom.mockImplementation((table: string) => {
      if (table === 'users') {
        const chain: Record<string, jest.Mock> = {
          upsert: jest.fn(),
          select: jest.fn(),
          single: jest.fn().mockResolvedValue({ data: { id: 'user-uuid', status: 'active' }, error: null }),
        };
        chain.upsert.mockReturnValue(chain);
        chain.select.mockReturnValue(chain);
        return chain;
      }
      if (table === 'learner_profiles') {
        const chain: Record<string, jest.Mock> = {
          select: jest.fn(),
          eq: jest.fn(),
          maybeSingle: jest.fn().mockResolvedValue({ data: null, error: null }),
          insert: jest.fn().mockResolvedValue({ error: null }),
        };
        chain.select.mockReturnValue(chain);
        chain.eq.mockReturnValue(chain);
        return chain;
      }
      if (table === 'sessions') {
        return { insert: jest.fn().mockResolvedValue({ error: null }) };
      }
      return { insert: mockInsert };
    });
    (StrKey.isValidEd25519PublicKey as jest.Mock).mockReturnValue(true);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  // ---------------------------------------------------------------------------
  // generateNonce
  // ---------------------------------------------------------------------------
  describe('generateNonce', () => {
    it('should return nonce, expiresAt and a canonical challenge message', async () => {
      const result = await service.generateNonce(validWallet);

      expect(result).toHaveProperty('nonce');
      expect(result).toHaveProperty('expiresAt');
      expect(result).toHaveProperty('message');
      expect(typeof result.nonce).toBe('string');
      expect(result.nonce).toHaveLength(64);
      expect(/^[a-f0-9]+$/.test(result.nonce)).toBe(true);
    });

    it('should generate unique nonces on each call', async () => {
      const result1 = await service.generateNonce(validWallet);
      const result2 = await service.generateNonce(validWallet);

      expect(result1.nonce).not.toBe(result2.nonce);
    });

    it('should set expiresAt to approximately 5 minutes from now', async () => {
      const before = Date.now();
      const result = await service.generateNonce(validWallet);
      const after = Date.now();

      const expiresAtTime = new Date(result.expiresAt).getTime();
      const fiveMinutes = 5 * 60 * 1000;
      const tolerance = 2000;

      expect(expiresAtTime).toBeGreaterThanOrEqual(before + fiveMinutes - tolerance);
      expect(expiresAtTime).toBeLessThanOrEqual(after + fiveMinutes + tolerance);
    });

    it('should return a challenge message bound to this environment, wallet and nonce', async () => {
      const result = await service.generateNonce(validWallet);

      const envelope = JSON.parse(result.message);
      expect(envelope.domain).toBe(CHALLENGE_DOMAIN);
      expect(envelope.address).toBe(validWallet);
      expect(envelope.uri).toBe(CHALLENGE_URI);
      expect(envelope.nonce).toBe(result.nonce);
      expect(envelope.version).toBe('1.0.0');
      expect(envelope.issuedAt).toBeDefined();
      expect(envelope.expirationTime).toBe(result.expiresAt);
      expect(envelope.networkPassphrase).toBe(NETWORK_PASSPHRASE);
    });

    it('should store nonce in database with the exact challenge message hash', async () => {
      const result = await service.generateNonce(validWallet);

      expect(mockSupabaseService.getServiceRoleClient).toHaveBeenCalled();
      expect(mockFrom).toHaveBeenCalledWith('nonces');
      const expectedHash = createHash('sha256').update(result.message, 'utf8').digest('hex');
      expect(mockInsert).toHaveBeenCalledWith(
        expect.objectContaining({
          wallet_address: validWallet,
          nonce: expect.any(String),
          expires_at: expect.any(String),
          issued_at: expect.any(String),
          message_hash: expectedHash,
        }),
      );
    });

    it('should throw InternalServerErrorException when database insert fails', async () => {
      mockInsert.mockResolvedValue({ error: { message: 'Database connection failed' } });

      await expect(service.generateNonce(validWallet)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  // ---------------------------------------------------------------------------
  // verifySignature — domain-bound challenge verification
  // ---------------------------------------------------------------------------
  describe('verifySignature', () => {
    const validNonce = 'a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890';
    const validSignature = Buffer.alloc(64).toString('base64');
    const futureExpiry = new Date(Date.now() + 5 * 60 * 1000).toISOString();

    const defaultNonceRecord = { id: 'nonce-uuid', expires_at: futureExpiry };

    type NonceResult = { data: object | null; error: { message: string } | null };

    interface TestNonceRecord {
      id: string;
      expires_at: string;
      issued_at: string;
      message_hash: string;
    }

    /** Nonce record for a challenge issued ~1 minute ago, valid for 5 more. */
    function buildNonceRecord(overrides: Partial<TestNonceRecord> = {}): TestNonceRecord {
      const issuedAt = new Date(Date.now() - 60 * 1000);
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
      const message = buildChallengeMessage(validWallet, validNonce, issuedAt, expiresAt);
      return {
        id: 'nonce-uuid',
        expires_at: expiresAt.toISOString(),
        issued_at: issuedAt.toISOString(),
        message_hash: createHash('sha256').update(message, 'utf8').digest('hex'),
        ...overrides,
      };
    }

    function setupMocks({
      nonceResult = { data: defaultNonceRecord, error: null },
      markUsedResult = { error: null },
      signatureValid = true,
      strKeyValid = true,
    }: {
      nonceResult?: NonceResult;
      markUsedResult?: { error: unknown };
      signatureValid?: boolean;
      strKeyValid?: boolean;
    } = {}) {
      const mockKeypair = { verify: jest.fn().mockReturnValue(signatureValid) };
      (Keypair.fromPublicKey as jest.Mock).mockReturnValue(mockKeypair);
      (StrKey.isValidEd25519PublicKey as jest.Mock).mockReturnValue(strKeyValid);

      mockFrom.mockImplementation((table: string) => {
        if (table === 'nonces') {
          const updateChain = { eq: jest.fn().mockResolvedValue(markUsedResult) };
          const chain: Record<string, jest.Mock> = {
            select: jest.fn(),
            eq: jest.fn(),
            is: jest.fn(),
            single: jest.fn().mockResolvedValue(nonceResult),
            update: jest.fn().mockReturnValue(updateChain),
          };
          chain.select.mockReturnValue(chain);
          chain.eq.mockReturnValue(chain);
          chain.is.mockReturnValue(chain);
          return chain;
        }
        return { insert: mockInsert };
      });

      return { mockKeypair };
    }

    const validDto: VerifyRequestDto = { wallet: validWallet, nonce: validNonce, signature: validSignature };

    // --- legacy raw scheme (deprecated, migration window) -------------------

    it('should resolve without error when nonce and signature are valid (legacy raw)', async () => {
      setupMocks();
      await expect(service.verifySignature(validDto)).resolves.toBeUndefined();
    });

    it('should throw UnauthorizedException (AUTH_NONCE_NOT_FOUND) when nonce does not exist', async () => {
      setupMocks({ nonceResult: { data: null, error: { message: 'No rows found' } } });

      await expect(service.verifySignature(validDto)).rejects.toMatchObject({
        response: { code: 'AUTH_NONCE_NOT_FOUND' },
      });
    });

    it('should throw UnauthorizedException (AUTH_NONCE_NOT_FOUND) when nonce is already used', async () => {
      // A used nonce has used_at set — .is('used_at', null) excludes it → same NOT_FOUND error
      setupMocks({ nonceResult: { data: null, error: { message: 'No rows found' } } });

      await expect(service.verifySignature(validDto)).rejects.toMatchObject({
        response: { code: 'AUTH_NONCE_NOT_FOUND' },
      });
    });

    it('should throw UnauthorizedException (AUTH_NONCE_EXPIRED) when nonce is past expiry', async () => {
      const expiredDate = new Date(Date.now() - 1000).toISOString();
      setupMocks({
        nonceResult: { data: { id: 'nonce-uuid', expires_at: expiredDate }, error: null },
      });

      await expect(service.verifySignature(validDto)).rejects.toMatchObject({
        response: { code: 'AUTH_NONCE_EXPIRED' },
      });
    });

    it('should throw UnauthorizedException (AUTH_SIGNATURE_INVALID) when StrKey validation fails', async () => {
      setupMocks({ strKeyValid: false });

      await expect(service.verifySignature(validDto)).rejects.toMatchObject({
        response: { code: 'AUTH_SIGNATURE_INVALID' },
      });
    });

    it('should throw UnauthorizedException (AUTH_SIGNATURE_INVALID) when legacy signature does not verify', async () => {
      setupMocks({ signatureValid: false });

      await expect(service.verifySignature(validDto)).rejects.toMatchObject({
        response: { code: 'AUTH_SIGNATURE_INVALID' },
      });
    });

    it('should throw UnauthorizedException (AUTH_SIGNATURE_INVALID) when Keypair throws an unexpected error', async () => {
      setupMocks();
      (Keypair.fromPublicKey as jest.Mock).mockImplementation(() => {
        throw new Error('Unexpected error');
      });

      await expect(service.verifySignature(validDto)).rejects.toMatchObject({
        response: { code: 'AUTH_SIGNATURE_INVALID' },
      });
    });

    it('should verify a legacy signature using Stellar Keypair with nonce bytes and base64 signature', async () => {
      const { mockKeypair } = setupMocks();
      await service.verifySignature(validDto);

      expect(Keypair.fromPublicKey).toHaveBeenCalledWith(validWallet);
      expect(mockKeypair.verify).toHaveBeenCalledWith(
        Buffer.from(validNonce),
        Buffer.from(validSignature, 'base64'),
      );
    });

    it('should reject legacy raw nonce signatures when AUTH_ALLOW_LEGACY_RAW_SIGNATURES is false', async () => {
      const serviceWithLegacyOff = createServiceWithConfig({ AUTH_ALLOW_LEGACY_RAW_SIGNATURES: 'false' });
      // A signature that WOULD verify (mock verify returns true) — the guard
      // must reject it purely because the legacy scheme is disabled.
      const { mockKeypair } = setupMocks({ signatureValid: true });
      const legacyDto: VerifyRequestDto = { ...validDto, signatureType: 'raw' };

      await expect(serviceWithLegacyOff.verifySignature(legacyDto)).rejects.toMatchObject({
        response: { code: 'AUTH_LEGACY_SIGNATURE_DISABLED' },
      });
      expect(mockKeypair.verify).not.toHaveBeenCalled();
    });

    it('should reject legacy raw nonce signatures after the sunset date even when the flag is still true', async () => {
      // AUTH_ALLOW_LEGACY_RAW_SIGNATURES=true but the sunset has passed — the
      // runtime cutoff must close the replayable scheme anyway (issue #118).
      const servicePastSunset = createServiceWithConfig({
        AUTH_ALLOW_LEGACY_RAW_SIGNATURES: 'true',
        AUTH_LEGACY_SIGNATURES_SUNSET: '2020-01-01',
      });
      const { mockKeypair } = setupMocks({ signatureValid: true });
      const legacyDto: VerifyRequestDto = { ...validDto, signatureType: 'raw' };

      await expect(servicePastSunset.verifySignature(legacyDto)).rejects.toMatchObject({
        response: { code: 'AUTH_LEGACY_SIGNATURE_DISABLED' },
      });
      expect(mockKeypair.verify).not.toHaveBeenCalled();
    });

    it('should accept legacy raw nonce signatures while the flag is true and the sunset is in the future', async () => {
      const serviceFutureSunset = createServiceWithConfig({
        AUTH_ALLOW_LEGACY_RAW_SIGNATURES: 'true',
        AUTH_LEGACY_SIGNATURES_SUNSET: '2999-01-01',
      });
      const { mockKeypair } = setupMocks();
      const legacyDto: VerifyRequestDto = { ...validDto, signatureType: 'raw' };

      await expect(serviceFutureSunset.verifySignature(legacyDto)).resolves.toBeUndefined();
      expect(mockKeypair.verify).toHaveBeenCalledWith(
        Buffer.from(validNonce),
        Buffer.from(validSignature, 'base64'),
      );
    });

    // --- canonical envelope: native (signatureType 'envelope') --------------

    it('should accept a native signature over the canonical envelope (signatureType envelope)', async () => {
      const record = buildNonceRecord();
      const { mockKeypair } = setupMocks({ nonceResult: { data: record, error: null } });
      const message = buildChallengeMessage(validWallet, validNonce, new Date(record.issued_at), new Date(record.expires_at));
      const dto: VerifyRequestDto = { ...validDto, signatureType: 'envelope', message };

      await expect(service.verifySignature(dto)).resolves.toBeUndefined();

      expect(mockKeypair.verify).toHaveBeenCalledWith(
        Buffer.from(message, 'utf8'),
        Buffer.from(validSignature, 'base64'),
      );
    });

    it('should verify a canonical signature against the reconstructed message when the client omits message', async () => {
      const record = buildNonceRecord();
      const { mockKeypair } = setupMocks({ nonceResult: { data: record, error: null } });
      const dto: VerifyRequestDto = { ...validDto, signatureType: 'envelope' };

      await expect(service.verifySignature(dto)).resolves.toBeUndefined();

      const message = buildChallengeMessage(validWallet, validNonce, new Date(record.issued_at), new Date(record.expires_at));
      expect(mockKeypair.verify).toHaveBeenCalledWith(
        Buffer.from(message, 'utf8'),
        Buffer.from(validSignature, 'base64'),
      );
    });

    it('should reject a client-supplied message that does not match the stored challenge hash', async () => {
      const record = buildNonceRecord();
      setupMocks({ nonceResult: { data: record, error: null } });
      const message = buildChallengeMessage(validWallet, validNonce, new Date(record.issued_at), new Date(record.expires_at));
      const tampered = message.replace('authenticate your wallet', 'authenticate');
      const dto: VerifyRequestDto = { ...validDto, signatureType: 'envelope', message: tampered };

      await expect(service.verifySignature(dto)).rejects.toMatchObject({
        response: { code: 'AUTH_CHALLENGE_MISMATCH' },
      });
    });

    it('should reject a canonical challenge whose envelope expirationTime has passed', async () => {
      const issuedAt = new Date(Date.now() - 10 * 60 * 1000);
      const expiresAt = new Date(Date.now() - 5 * 60 * 1000); // envelope expired
      const message = buildChallengeMessage(validWallet, validNonce, issuedAt, expiresAt);
      const record = buildNonceRecord({
        expires_at: futureExpiry, // DB row still valid — envelope expiry is enforced separately
        issued_at: issuedAt.toISOString(),
        message_hash: createHash('sha256').update(message, 'utf8').digest('hex'),
      });
      setupMocks({ nonceResult: { data: record, error: null } });
      const dto: VerifyRequestDto = { ...validDto, signatureType: 'envelope', message };

      await expect(service.verifySignature(dto)).rejects.toMatchObject({
        response: { code: 'AUTH_NONCE_EXPIRED' },
      });
    });

    it('should reject canonical verification when the nonce row has no stored challenge hash', async () => {
      setupMocks({
        nonceResult: {
          data: { id: 'nonce-uuid', expires_at: futureExpiry, issued_at: null, message_hash: null },
          error: null,
        },
      });
      const message = buildChallengeMessage(validWallet, validNonce, new Date(), new Date(Date.now() + 5 * 60 * 1000));
      const dto: VerifyRequestDto = { ...validDto, signatureType: 'envelope', message };

      await expect(service.verifySignature(dto)).rejects.toMatchObject({
        response: { code: 'AUTH_SIGNATURE_INVALID' },
      });
    });

    // --- canonical envelope: browser (signatureType 'sep0043', SEP-53) ------

    it('should accept a SEP-53 browser signature over the canonical envelope (signatureType sep0043)', async () => {
      const record = buildNonceRecord();
      const { mockKeypair } = setupMocks({ nonceResult: { data: record, error: null } });
      const message = buildChallengeMessage(validWallet, validNonce, new Date(record.issued_at), new Date(record.expires_at));
      const dto: VerifyRequestDto = { ...validDto, signatureType: 'sep0043', message };

      await expect(service.verifySignature(dto)).resolves.toBeUndefined();

      const digest = createHash('sha256').update(SEP_53_PREFIX + message, 'utf8').digest();
      expect(mockKeypair.verify).toHaveBeenCalledWith(digest, Buffer.from(validSignature, 'base64'));
    });

    it('should reject a SEP-53 signature whose envelope domain does not match our host', async () => {
      const record = buildNonceRecord();
      const message = buildChallengeMessage(validWallet, validNonce, new Date(record.issued_at), new Date(record.expires_at));
      const foreignMessage = message.replace('"domain": "localhost:3000"', '"domain": "evil.example.com"');
      // Simulates a nonce row whose stored binding points at a foreign domain
      // (e.g. a challenge issued by another environment being replayed here).
      const tamperedRecord = buildNonceRecord({
        message_hash: createHash('sha256').update(foreignMessage, 'utf8').digest('hex'),
      });
      setupMocks({ nonceResult: { data: tamperedRecord, error: null } });
      const dto: VerifyRequestDto = { ...validDto, signatureType: 'sep0043', message: foreignMessage };

      await expect(service.verifySignature(dto)).rejects.toMatchObject({
        response: { code: 'AUTH_CHALLENGE_DOMAIN_MISMATCH' },
      });
    });

    it('should reject a canonical signature when the envelope network passphrase does not match', async () => {
      const record = buildNonceRecord();
      const message = buildChallengeMessage(validWallet, validNonce, new Date(record.issued_at), new Date(record.expires_at));
      const foreignMessage = message.replace(NETWORK_PASSPHRASE, 'Public Global Stellar Network ; September 2015');
      const tamperedRecord = buildNonceRecord({
        message_hash: createHash('sha256').update(foreignMessage, 'utf8').digest('hex'),
      });
      setupMocks({ nonceResult: { data: tamperedRecord, error: null } });
      const dto: VerifyRequestDto = { ...validDto, signatureType: 'sep0043', message: foreignMessage };

      await expect(service.verifySignature(dto)).rejects.toMatchObject({
        response: { code: 'AUTH_CHALLENGE_NETWORK_MISMATCH' },
      });
    });

    it('should mark nonce as used after successful verification', async () => {
      setupMocks();
      await service.verifySignature(validDto);

      expect(mockFrom).toHaveBeenCalledWith('nonces');
    });
  });

  // ---------------------------------------------------------------------------
  // generateTokens — upserts user, signs JWT tokens, stores session
  // ---------------------------------------------------------------------------
  describe('generateTokens', () => {
    const defaultUserRecord = { id: 'user-uuid', status: 'active' };

    function setupMocks({
      userResult = { data: defaultUserRecord, error: null },
      sessionResult = { error: null },
    } = {}) {
      mockFrom.mockImplementation((table: string) => {
        if (table === 'users') {
          const chain: Record<string, jest.Mock> = {
            upsert: jest.fn(),
            select: jest.fn(),
            single: jest.fn().mockResolvedValue(userResult),
          };
          chain.upsert.mockReturnValue(chain);
          chain.select.mockReturnValue(chain);
          return chain;
        }
        if (table === 'learner_profiles') {
          const chain: Record<string, jest.Mock> = {
            select: jest.fn(),
            eq: jest.fn(),
            maybeSingle: jest.fn().mockResolvedValue({ data: null, error: null }),
            insert: jest.fn().mockResolvedValue({ error: null }),
          };
          chain.select.mockReturnValue(chain);
          chain.eq.mockReturnValue(chain);
          return chain;
        }
        if (table === 'sessions') {
          return { insert: jest.fn().mockResolvedValue(sessionResult) };
        }
        return { insert: mockInsert };
      });
    }

    it('should return accessToken, refreshToken, expiresIn and tokenType', async () => {
      setupMocks();
      const result = await service.generateTokens(validWallet);

      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
      expect(result.expiresIn).toBe(900);
      expect(result.tokenType).toBe('Bearer');
    });

    it('should sign access token with payload { wallet, type: access } and 15m expiration', async () => {
      setupMocks();
      await service.generateTokens(validWallet);

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        { wallet: validWallet, type: 'access', role: null },
        expect.objectContaining({ expiresIn: '15m' }),
      );
    });

    it('should sign refresh token with payload { wallet, type: refresh } and 7d expiration', async () => {
      setupMocks();
      await service.generateTokens(validWallet);

      expect(mockJwtService.sign).toHaveBeenCalledWith(
        { wallet: validWallet, type: 'refresh' },
        expect.objectContaining({ expiresIn: '7d' }),
      );
    });

    it('should throw UnauthorizedException (AUTH_USER_BLOCKED) when user account is blocked', async () => {
      setupMocks({ userResult: { data: { id: 'user-uuid', status: 'blocked' }, error: null } });

      await expect(service.generateTokens(validWallet)).rejects.toMatchObject({
        response: { code: 'AUTH_USER_BLOCKED' },
      });
    });

    it('should throw InternalServerErrorException (DATABASE_USER_UPSERT_FAILED) when user upsert fails', async () => {
      setupMocks({ userResult: { data: null, error: { message: 'DB error' } } });

      await expect(service.generateTokens(validWallet)).rejects.toMatchObject({
        response: { code: 'DATABASE_USER_UPSERT_FAILED' },
      });
    });

    it('should throw InternalServerErrorException (DATABASE_SESSION_CREATE_FAILED) when session insert fails', async () => {
      setupMocks({ sessionResult: { error: { message: 'DB error' } } });

      await expect(service.generateTokens(validWallet)).rejects.toMatchObject({
        response: { code: 'DATABASE_SESSION_CREATE_FAILED' },
      });
    });
  });

  // ---------------------------------------------------------------------------
  // register
  // ---------------------------------------------------------------------------
  describe('register', () => {
    const registerDto = {
      walletAddress: validWallet,
      username: 'testuser',
      displayName: 'Test User',
      termsAccepted: 'true',
    };

    const mockUser = {
      id: 'user-uuid',
      wallet_address: validWallet,
      username: 'testuser',
      display_name: 'Test User',
      avatar_url: 'https://example.com/avatar.png',
      created_at: new Date().toISOString(),
    };

    beforeEach(() => {
      mockUsersRepository.findByWallet.mockResolvedValue(null);
      mockUsersRepository.checkUsernameExists.mockResolvedValue(false);
      mockUsersRepository.createProfile.mockResolvedValue(mockUser);
      mockUsersRepository.uploadAvatar.mockResolvedValue('https://example.com/avatar.png');

      // Mock findOrCreateUser internal behavior via Supabase mock
      mockFrom.mockImplementation((table: string) => {
        if (table === 'users') {
          const chain: Record<string, jest.Mock> = {
            upsert: jest.fn(),
            select: jest.fn(),
            single: jest.fn().mockResolvedValue({ data: { id: 'user-uuid', status: 'active' }, error: null }),
          };
          chain.upsert.mockReturnValue(chain);
          chain.select.mockReturnValue(chain);
          return chain;
        }
        if (table === 'learner_profiles') {
          const chain: Record<string, jest.Mock> = {
            select: jest.fn(),
            eq: jest.fn(),
            maybeSingle: jest.fn().mockResolvedValue({ data: null, error: null }),
            insert: jest.fn().mockResolvedValue({ error: null }),
          };
          chain.select.mockReturnValue(chain);
          chain.eq.mockReturnValue(chain);
          return chain;
        }
        if (table === 'sessions') {
          return { insert: jest.fn().mockResolvedValue({ error: null }) };
        }
        return { insert: mockInsert };
      });
    });

    it('should register a new user successfully without image', async () => {
      const result = await service.register(registerDto);

      expect(mockUsersRepository.findByWallet).toHaveBeenCalledWith(validWallet);
      expect(mockUsersRepository.checkUsernameExists).toHaveBeenCalledWith('testuser');
      expect(mockUsersRepository.createProfile).toHaveBeenCalledWith({
        wallet: validWallet,
        username: 'testuser',
        displayName: 'Test User',
        avatarUrl: null,
      });
      expect(result.user.walletAddress).toBe(validWallet);
      expect(result.accessToken).toBeDefined();
    });

    it('should register a new user successfully with profile image', async () => {
      const mockFile = { originalname: 'avatar.png', buffer: Buffer.from('test'), mimetype: 'image/png' };
      const result = await service.register(registerDto, mockFile);

      expect(mockUsersRepository.uploadAvatar).toHaveBeenCalledWith(validWallet, mockFile);
      expect(mockUsersRepository.createProfile).toHaveBeenCalledWith(
        expect.objectContaining({
          avatarUrl: 'https://example.com/avatar.png',
        }),
      );
      expect(result.user.avatarUrl).toBe('https://example.com/avatar.png');
    });

    it('should throw ConflictException if wallet already exists', async () => {
      mockUsersRepository.findByWallet.mockResolvedValue({ id: 'existing' });

      await expect(service.register(registerDto)).rejects.toThrow(ConflictException);
      await expect(service.register(registerDto)).rejects.toMatchObject({
        response: { code: 'AUTH_WALLET_EXISTS' },
      });
    });

    it('should throw ConflictException if username is taken', async () => {
      mockUsersRepository.checkUsernameExists.mockResolvedValue(true);

      await expect(service.register(registerDto)).rejects.toThrow(ConflictException);
      await expect(service.register(registerDto)).rejects.toMatchObject({
        response: { code: 'AUTH_USERNAME_TAKEN' },
      });
    });
  });
});
