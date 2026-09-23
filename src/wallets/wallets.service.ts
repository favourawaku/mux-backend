import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  OnModuleDestroy,
  Optional,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaClient } from '../generated/prisma/client';
import {
  Wallet,
  WalletNetwork,
  WalletStatus,
  WalletStatusResponse,
  canTransitionWalletStatus,
} from './domain/wallet.model';
import {
  DecryptionError,
  EncryptionService,
} from '../encryption/encryption.service';
import { SafeLogger } from '../common/safe-logger';
import { KeyDecryptionException } from '../key-management/exceptions/key-decryption.exception';
import { KeyManagementService } from '../key-management/key-management.service';
import { KeyType } from '../key-management/domain/key-types';
import { WebhookEventEmitterService } from '../webhooks/webhook-event-emitter.service';
import { WalletApiMetricsService } from './wallet-api-metrics.service';
import { WalletRetryService } from './wallet-retry.service';
import * as crypto from 'crypto';
import {
  StructuredLogger,
  LogContext,
} from '../common/logging/structured-logger';
import { TransactionStatus } from '../transactions/domain/transaction.model';

/** Wallet shape safe to return from the API (no encrypted secret material). */
export type PublicWallet = Omit<Wallet, 'encryptedSecret'>;

/**
 * Stable, typed error codes for wallet nickname validation failures.
 *
 * These codes are part of the public API contract: clients must be able to
 * branch on them without parsing human-readable messages, and they must never
 * embed raw key material or secrets.
 */
export enum WalletNicknameErrorCode {
  INVALID_FORMAT = 'WALLET_NICKNAME_INVALID_FORMAT',
  INVALID_LENGTH = 'WALLET_NICKNAME_INVALID_LENGTH',
  INVALID_CHARSET = 'WALLET_NICKNAME_INVALID_CHARSET',
  RESERVED = 'WALLET_NICKNAME_RESERVED',
  CONFLICT = 'WALLET_NICKNAME_CONFLICT',
  NOT_OWNER = 'WALLET_NICKNAME_NOT_OWNER',
}

/** Nickname length bounds (inclusive), measured after normalization. */
export const WALLET_NICKNAME_MIN_LENGTH = 3;
export const WALLET_NICKNAME_MAX_LENGTH = 32;

/**
 * Allowed nickname charset: lowercase letters, digits, and internal
 * hyphens/underscores. Anchored so the whole (normalized) value must match.
 */
export const WALLET_NICKNAME_PATTERN = /^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$/;

/**
 * Nicknames that would collide with routing/identity semantics and must not be
 * claimable by users.
 */
export const WALLET_NICKNAME_RESERVED = new Set<string>([
  'admin',
  'administrator',
  'root',
  'system',
  'support',
  'mux',
  'official',
  'treasury',
  'null',
  'undefined',
]);

/**
 * Normalize a raw nickname into its canonical, comparable form.
 *
 * Normalization is intentionally conservative: trim surrounding whitespace,
 * Unicode NFKC-fold, and lowercase. It does NOT strip internal characters so
 * that invalid input is rejected rather than silently rewritten.
 */
export function normalizeWalletNickname(raw: string): string {
  return raw.normalize('NFKC').trim().toLowerCase();
}

/**
 * Validate a raw nickname and return its normalized form.
 *
 * Throws a BadRequestException carrying a stable error code for any invalid
 * input. Never includes the raw value in the message to avoid echoing
 * potentially sensitive user input into logs.
 */
export function validateWalletNickname(raw: unknown): string {
  if (typeof raw !== 'string') {
    throw new BadRequestException({
      code: WalletNicknameErrorCode.INVALID_FORMAT,
      message: 'Nickname must be a string',
    });
  }

  const normalized = normalizeWalletNickname(raw);

  if (
    normalized.length < WALLET_NICKNAME_MIN_LENGTH ||
    normalized.length > WALLET_NICKNAME_MAX_LENGTH
  ) {
    throw new BadRequestException({
      code: WalletNicknameErrorCode.INVALID_LENGTH,
      message: `Nickname must be between ${WALLET_NICKNAME_MIN_LENGTH} and ${WALLET_NICKNAME_MAX_LENGTH} characters`,
    });
  }

  if (!WALLET_NICKNAME_PATTERN.test(normalized)) {
    throw new BadRequestException({
      code: WalletNicknameErrorCode.INVALID_CHARSET,
      message:
        'Nickname may only contain lowercase letters, digits, hyphens, and underscores, and must start and end with a letter or digit',
    });
  }

  if (WALLET_NICKNAME_RESERVED.has(normalized)) {
    throw new BadRequestException({
      code: WalletNicknameErrorCode.RESERVED,
      message: 'Nickname is reserved',
    });
  }

  return normalized;
}

export interface CreateWalletRequest {
  userId: string;
  network: WalletNetwork;
}

export interface WalletListFilters {
  userId?: string;
  network?: WalletNetwork;
  status?: WalletStatus;
  /** Include archived wallets in the results (excluded by default). */
  includeArchived?: boolean;
  limit?: number;
  offset?: number;
  /** Enable load test synthetic data generation. */
  loadTestMode?: boolean;
}

export interface WalletListResult {
  data: PublicWallet[];
  total: number;
  limit: number;
  offset: number;
  hasMore: boolean;
}

export interface WalletCreationResult {
  wallet: Wallet;
  privateKey: string;
}

export interface SigningResult {
  signature: string;
  transactionHash?: string;
}

/**
 * Caller identity for nickname mutations. Authorization is deny-by-default:
 * only the wallet owner or an explicitly authorized delegate may set a
 * nickname.
 */
export interface WalletNicknameActor {
  userId: string;
  /** When true, the actor is acting as an authorized delegate. */
  isDelegate?: boolean;
}

@Injectable()
export class WalletsService implements OnModuleDestroy {
  private readonly logger = new StructuredLogger(WalletsService.name);
  private prisma: PrismaClient;

  constructor(
    private encryptionService: EncryptionService,
    private configService: ConfigService,
    private keyManagementService: KeyManagementService,
    @Optional() private webhookEventEmitter?: WebhookEventEmitterService,
    @Optional() private walletRetryService?: WalletRetryService,
    @Optional() private walletApiMetrics?: WalletApiMetricsService,
  ) {
    this.prisma = new PrismaClient({} as any);
  }

  async onModuleDestroy() {
    await this.prisma.$disconnect();
  }

  async onModuleInit() {
    if (!this.encryptionService.validateConfiguration()) {
      throw new Error('Wallet encryption service configuration is invalid');
    }
    this.logger.logWithContext('Wallet service initialized', {
      operation: 'init',
      outcome: 'success',
    });
  }

  /**
   * Set or update the nickname for a wallet.
   *
   * Invariants:
   * - Only the wallet owner (or an authorized delegate) may mutate the
   *   nickname; all other callers are denied by default.
   * - The nickname is normalized (NFKC, trimmed, lowercased) before validation
   *   and persistence, so uniqueness is enforced on the canonical form.
   * - Nicknames are unique per owner (userId), not globally, so different users
   *   may reuse the same nickname.
   * - Validation failures return stable, typed error codes and never echo raw
   *   input or key material.
   */
  async setWalletNickname(
    walletId: string,
    nickname: string,
    actor: WalletNicknameActor,
  ): Promise<PublicWallet> {
    const startedAt = Date.now();

    const wallet = await this.prisma.wallet.findUnique({
      where: { id: walletId },
    });
    if (!wallet) {
      throw new NotFoundException(`Wallet with ID ${walletId} not found`);
    }

    // Deny-by-default authorization: owner or explicitly authorized delegate.
    const isOwner = wallet.userId === actor.userId;
    if (!isOwner && !actor.isDelegate) {
      this.recordMetric('set_nickname', 'failure', startedAt, wallet.network);
      throw new ForbiddenException({
        code: WalletNicknameErrorCode.NOT_OWNER,
        message: 'Only the wallet owner or an authorized delegate may set a nickname',
      });
    }

    const normalized = validateWalletNickname(nickname);

    // Per-owner uniqueness on the normalized value.
    const conflict = await this.prisma.wallet.findFirst({
      where: {
        userId: wallet.userId,
        nickname: normalized,
        NOT: { id: walletId },
      },
    });
    if (conflict) {
      this.recordMetric('set_nickname', 'failure', startedAt, wallet.network);
      throw new ConflictException({
        code: WalletNicknameErrorCode.CONFLICT,
        message: 'Nickname is already in use for this account',
      });
    }

    try {
      const updated = await this.prisma.wallet.update({
        where: { id: walletId },
        data: { nickname: normalized },
      });
      this.recordMetric('set_nickname', 'success', startedAt, wallet.network);
      return this.toPublicWallet(this.mapPrismaWalletToDomain(updated));
    } catch (error) {
      // P2002: unique constraint violation on (userId, nickname) — a concurrent
      // request won the race. Fail closed with a stable conflict code.
      if (error && typeof error === 'object' && (error as any).code === 'P2002') {
        this.recordMetric('set_nickname', 'failure', startedAt, wallet.network);
        throw new ConflictException({
          code: WalletNicknameErrorCode.CONFLICT,
          message: 'Nickname is already in use for this account',
        });
      }
      this.logger.error('Failed to set wallet nickname:', error);
      this.recordMetric('set_nickname', 'failure', startedAt, wallet.network);
      throw new Error('Failed to set wallet nickname');
    }
  }

  /**
   * Creates a new wallet for the given user/network.
   *
   * #494 Rollback strategy:
   * - All DB and key operations are wrapped in a Prisma transaction.
   * - If Horizon funding fails (TESTNET), the error is caught and logged; the
   *   wallet creation does NOT roll back because funding is best-effort.
   * - If key generation or DB persistence fails, the transaction rolls back
   *   automatically, leaving no partial wallet record.
   */
  async createWallet(
    request: CreateWalletRequest,
  ): Promise<WalletCreationResult> {
    const startedAt = Date.now();
    const { userId, network } = request;

    const existingWallet = await this.prisma.wallet.findFirst({
      where: { userId, network },
    });
    if (existingWallet) {
      throw new ConflictException(`User already has a wallet on ${network}`);
    }

    let wallet: Wallet;
    let privateKey: string;

    try {
      // Key generation (outside the DB transaction so we can roll back cleanly)
      const key = await this.generateKeyWithRetry('key_generation', {
        keyType: KeyType.STELLAR_ED25519,
        metadata: { userId, network },
      });
      privateKey = this.encryptionService.deserializeAndDecrypt(
        key.encryptedData,
      );

      // Atomic DB write — rolled back automatically if anything throws
      const created = await this.prisma.$transaction(async (tx) => {
        return tx.wallet.create({
          data: {
            userId,
            publicKey: key.publicKey,
            encryptedSecret: key.encryptedData,
            network,
            status: WalletStatus.ACTIVE,
            encryptionVersion: key.encryptionVersion,
            secretVersion: 1,
            keyVersion: 1,
          },
        });
      });

      wallet = this.mapPrismaWalletToDomain(created);
    } catch (error) {
      // Prisma P2002: unique constraint violation on (network, publicKey)
      // This should be extraordinarily rare (key-space collision) but must be
      // handled explicitly so callers receive a clear 409 rather than a 500.
      if (
        error &&
        typeof error === 'object' &&
        (error as any).code === 'P2002' &&
        (error as any).meta?.target?.includes('publicKey')
      ) {
        this.logger.error(
          `Public key collision detected during wallet creation for user ${userId} on ${network}`,
        );
        this.recordMetric('create', 'failure', startedAt, network);
        throw new ConflictException(
          `The generated public key already exists on ${network}. Please retry — a new unique key will be generated.`,
        );
      }
      this.logger.error('Failed to create wallet:', error);
      this.recordMetric('create', 'failure', startedAt, network);
      throw new Error('Wallet creation failed');
    }

    this.emitDomainEvent('wallet.created', () =>
      this.webhookEventEmitter?.emitWalletCreated({
        walletId: wallet.id,
        userId: wallet.userId,
        publicKey: wallet.publicKey,
        network: wallet.network,
        status: wallet.status,
      }),
    );
    this.recordMetric('create', 'success', startedAt, network);
    return { wallet, privateKey };
  }

  async findWalletById(walletId: string): Promise<Wallet> {
    const wallet = await this.prisma.wallet.findUnique({
      where: { id: walletId },
    });
    if (!wallet)
      throw new NotFoundException(`Wallet with ID ${walletId} not found`);
    return this.mapPrismaWalletToDomain(wallet);
  }

  /**
   * Look up a wallet by its Stellar public key (address) and network.
   *
   * Address uniqueness is enforced at the DB level via the
   * @@unique([network, publicKey]) constraint.  This method provides an
   * explicit, human-readable lookup path for consumers who know the on-chain
   * address but not the internal wallet ID.
   *
   * @param publicKey  Stellar public key (G-address or M-address).
   * @param network    Network the key lives on (MAINNET / TESTNET).
   * @throws NotFoundException when no wallet with that key exists on the network.
   */
  async findByPublicKey(
    publicKey: string,
    network: WalletNetwork,
  ): Promise<PublicWallet> {
    const wallet = await this.prisma.wallet.findUnique({
      where: { network_publicKey: { network, publicKey } },
    });
    if (!wallet) {
      throw new NotFoundException(
        `No wallet found for public key ${publicKey} on ${network}`,
      );
    }
    return this.toPublicWallet(this.mapPrismaWalletToDomain(wallet));
  }

  /**
   * Check whether a public key is already registered on a given network.
   *
   * Returns true if the address is taken, false if it is available.
   * Useful for pre-creation validation before key generation.
   */
  async isPublicKeyTaken(
    publicKey: string,
    network: WalletNetwork,
  ): Promise<boolean> {
    const count = await this.prisma.wallet.count({
      where: { publicKey, network },
    });
    return count > 0;
  }

  async findWalletByUser(
    userId: string,
    networ

/* … truncated 17262 chars — edit only what you need near the top … */
