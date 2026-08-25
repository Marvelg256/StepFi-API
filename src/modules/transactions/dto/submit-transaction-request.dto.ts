import { IsString, IsNotEmpty, IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum TransactionType {
  LOAN_CREATE = 'loan_create',
  LOAN_REPAY = 'loan_repay',
  DEPOSIT = 'deposit',
  WITHDRAW = 'withdraw',
  VENDOR_APPROVE = 'vendor_approve',
  VENDOR_SUSPEND = 'vendor_suspend',
}


/**
 * DTO for submitting a signed Stellar XDR transaction to the network.
 *
 * POST /transactions/submit enforces the following guarantees:
 * - The transaction source account (or, for fee-bump transactions, the inner
 *   source account) must equal the authenticated wallet, or the wallet must
 *   appear as an authorized address in the Soroban invocation auth. XDR in
 *   which the wallet is neither source nor authorizer is rejected with
 *   `TRANSACTION_SOURCE_MISMATCH`.
 * - The declared `type` must match the operations contained in the XDR
 *   (e.g. `deposit` must be a Soroban `deposit` invocation on the liquidity
 *   pool contract). Mismatches are rejected with `TRANSACTION_TYPE_MISMATCH`
 *   or `TRANSACTION_OPERATION_NOT_ALLOWED`.
 * - Submission is idempotent per transaction hash: re-submitting an already
 *   recorded hash returns the original record without a second Horizon
 *   submission (`duplicate: true` on the response).
 * - The local record is persisted before the Horizon submission, so
 *   persistence failures surface as errors rather than being silently dropped.
 */
export class SubmitTransactionRequestDto {
  @ApiProperty({
    description: 'Signed XDR transaction string to submit to the Stellar network',
    example: 'AAAAAgAAAAA...',
  })
  @IsString({ message: 'xdr must be a string' })
  @IsNotEmpty({ message: 'xdr must not be empty' })
  xdr: string;

  @ApiProperty({
    description: 'Transaction type for record classification',
    enum: TransactionType,
    example: TransactionType.DEPOSIT,
  })
  @IsEnum(TransactionType, {
    message: `type must be one of: ${Object.values(TransactionType).join(', ')}`,
  })
  type: TransactionType;
}
