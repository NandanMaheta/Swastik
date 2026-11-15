/**
 * Compile stub (S17, test-engineer). S19 fills in the codes and English messages of
 * specs/003-auth-core/contracts/error-codes.md; auth-error-codes.test.ts pins the contract.
 */
export const authErrorCodes = [] as const;

export type AuthErrorCode = (typeof authErrorCodes)[number];

export const authErrorMessages = {} as Readonly<Record<AuthErrorCode, string>>;

export function isAuthErrorCode(_code: unknown): _code is AuthErrorCode {
  throw new Error("not implemented");
}

export function authErrorMessage(_code: string | null | undefined): string {
  throw new Error("not implemented");
}
