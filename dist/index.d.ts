import * as _nestjs_common from '@nestjs/common';
import { CustomDecorator, createParamDecorator, NestModule, OnModuleInit, MiddlewareConsumer, DynamicModule, CanActivate, ExecutionContext } from '@nestjs/common';
import { createAuthMiddleware, getSession } from 'better-auth/api';
import { Auth as Auth$1 } from 'better-auth';
import { ApplicationConfig, DiscoveryService, MetadataScanner, HttpAdapterHost, Reflector } from '@nestjs/core';
import { Request, Response, NextFunction } from 'express';

/**
 * Allows unauthenticated (anonymous) access to a route or controller.
 * When applied, the AuthGuard will not perform authentication checks.
 */
declare const AllowAnonymous: () => CustomDecorator<string>;
/**
 * Marks a route or controller as having optional authentication.
 * When applied, the AuthGuard allows the request to proceed
 * even if no session is present.
 */
declare const OptionalAuth: () => CustomDecorator<string>;
/**
 * Specifies the user-level roles required to access a route or controller.
 * Checks ONLY the `user.role` field (from Better Auth's admin plugin).
 * Does NOT check organization member roles.
 *
 * Use this for system-wide admin protection (e.g., superadmin routes).
 *
 * @param roles - The roles required for access
 * @example
 * ```ts
 * @Roles(['admin'])  // Only users with user.role = 'admin' can access
 * ```
 */
declare const Roles: (roles: string[]) => CustomDecorator;
/**
 * Specifies the organization-level roles required to access a route or controller.
 * Checks ONLY the organization member role (from Better Auth's organization plugin).
 * Requires an active organization (`activeOrganizationId` in session).
 *
 * Use this for organization-scoped protection (e.g., org admin routes).
 *
 * @param roles - The organization roles required for access
 * @example
 * ```ts
 * @OrgRoles(['owner', 'admin'])  // Only org owners/admins can access
 * ```
 */
declare const OrgRoles: (roles: string[]) => CustomDecorator;
/**
 * @deprecated Use AllowAnonymous() instead.
 */
declare const Public: () => CustomDecorator<string>;
/**
 * @deprecated Use OptionalAuth() instead.
 */
declare const Optional: () => CustomDecorator<string>;
/**
 * Parameter decorator that extracts the user session from the request.
 * Provides easy access to the authenticated user's session data in controller methods.
 * Works with both HTTP and GraphQL execution contexts.
 */
declare const Session: ReturnType<typeof createParamDecorator>;
/**
 * Represents the context object passed to hooks.
 * This type is derived from the parameters of the createAuthMiddleware function.
 */
type AuthHookContext = Parameters<Parameters<typeof createAuthMiddleware>[0]>[0];
/**
 * Registers a method to be executed before a specific auth route is processed.
 * @param path - The auth route path that triggers this hook (must start with '/')
 */
declare const BeforeHook: (path?: `/${string}`) => CustomDecorator<symbol>;
/**
 * Registers a method to be executed after a specific auth route is processed.
 * @param path - The auth route path that triggers this hook (must start with '/')
 */
declare const AfterHook: (path?: `/${string}`) => CustomDecorator<symbol>;
/**
 * Class decorator that marks a provider as containing hook methods.
 * Must be applied to classes that use BeforeHook or AfterHook decorators.
 */
declare const Hook: () => ClassDecorator;

type Auth = any;
/**
 * NestJS module that integrates the Auth library with NestJS applications.
 * Provides authentication middleware, hooks, and exception handling.
 */
declare class AuthModule extends ConfigurableModuleClass implements NestModule, OnModuleInit {
    private readonly applicationConfig;
    private readonly discoveryService;
    private readonly metadataScanner;
    private readonly adapter;
    private readonly options;
    private readonly logger;
    private readonly basePath;
    constructor(applicationConfig: ApplicationConfig, discoveryService: DiscoveryService, metadataScanner: MetadataScanner, adapter: HttpAdapterHost, options: AuthModuleOptions);
    onModuleInit(): void;
    configure(consumer: MiddlewareConsumer): void;
    private setupHooks;
    static forRootAsync(options: typeof ASYNC_OPTIONS_TYPE): DynamicModule;
    static forRoot(options: typeof OPTIONS_TYPE): DynamicModule;
    /**
     * @deprecated Use the object-based signature: AuthModule.forRoot({ auth, ...options })
     */
    static forRoot(auth: Auth, options?: Omit<typeof OPTIONS_TYPE, "auth">): DynamicModule;
}

type AuthModuleOptions<A = Auth> = {
    auth: A;
    disableTrustedOriginsCors?: boolean;
    disableBodyParser?: boolean;
    /**
     * When set to `true`, enables raw body parsing and attaches it to `req.rawBody`.
     *
     * This is useful for webhook signature verification that requires the raw,
     * unparsed request body.
     *
     * **Important:** Since this library disables NestJS's built-in body parser,
     * NestJS's `rawBody: true` option in `NestFactory.create()` has no effect.
     * Use this option instead.
     *
     * @default false
     */
    enableRawBodyParser?: boolean;
    middleware?: (req: Request, res: Response, next: NextFunction) => void;
};
declare const ConfigurableModuleClass: _nestjs_common.ConfigurableModuleCls<AuthModuleOptions<any>, "forRoot", "create", {
    isGlobal: boolean;
    disableGlobalAuthGuard: boolean;
    disableControllers: boolean;
}>;
declare const OPTIONS_TYPE: AuthModuleOptions<any> & Partial<{
    isGlobal: boolean;
    disableGlobalAuthGuard: boolean;
    disableControllers: boolean;
}>;
declare const ASYNC_OPTIONS_TYPE: _nestjs_common.ConfigurableModuleAsyncOptions<AuthModuleOptions<any>, "create"> & Partial<{
    isGlobal: boolean;
    disableGlobalAuthGuard: boolean;
    disableControllers: boolean;
}>;

/**
 * NestJS service that provides access to the Better Auth instance
 * Use generics to support auth instances extended by plugins
 */
declare class AuthService<T extends {
    api: T["api"];
} = Auth$1> {
    private readonly options;
    constructor(options: AuthModuleOptions<T>);
    /**
     * Returns the API endpoints provided by the auth instance
     */
    get api(): T["api"];
    /**
     * Returns the complete auth instance
     * Access this for plugin-specific functionality
     */
    get instance(): T;
}

/**
 * Type representing a valid user session after authentication
 * Excludes null and undefined values from the session return type
 */
type BaseUserSession = NonNullable<Awaited<ReturnType<ReturnType<typeof getSession>>>>;
type UserSession = BaseUserSession & {
    user: BaseUserSession["user"] & {
        role?: string | string[];
    };
    session: BaseUserSession["session"] & {
        activeOrganizationId?: string;
    };
};
/**
 * NestJS guard that handles authentication for protected routes
 * Can be configured with @AllowAnonymous() or @OptionalAuth() decorators to modify authentication behavior
 */
declare class AuthGuard implements CanActivate {
    private readonly reflector;
    private readonly options;
    constructor(reflector: Reflector, options: AuthModuleOptions);
    /**
     * Validates if the current request is authenticated
     * Attaches session and user information to the request object
     * Supports HTTP, GraphQL and WebSocket execution contexts
     * @param context - The execution context of the current request
     * @returns True if the request is authorized to proceed, throws an error otherwise
     */
    canActivate(context: ExecutionContext): Promise<boolean>;
    /**
     * Checks if a role value matches any of the required roles
     * Handles both array and comma-separated string role formats
     * @param role - The role value to check (string, array, or undefined)
     * @param requiredRoles - Array of roles that grant access
     * @returns True if the role matches any required role
     */
    private matchesRequiredRole;
    /**
     * Fetches the user's role within an organization from the member table
     * Uses Better Auth's organization plugin API if available
     * @param headers - The request headers containing session cookies
     * @returns The member's role in the organization, or undefined if not found
     */
    private getMemberRoleInOrganization;
    /**
     * Checks if the user has any of the required roles in user.role only.
     * Used by @Roles() decorator for system-level role checks (admin plugin).
     * @param session - The user's session
     * @param requiredRoles - Array of roles that grant access
     * @returns True if user.role matches any required role
     */
    private checkUserRole;
    /**
     * Checks if the user has any of the required roles in their organization.
     * Used by @OrgRoles() decorator for organization-level role checks.
     * Requires an active organization in the session.
     * @param session - The user's session
     * @param headers - The request headers for API calls
     * @param requiredRoles - Array of roles that grant access
     * @returns True if org member role matches any required role
     */
    private checkOrgRole;
}

declare const BEFORE_HOOK_KEY: symbol;
declare const AFTER_HOOK_KEY: symbol;
declare const HOOK_KEY: symbol;
declare const AUTH_MODULE_OPTIONS_KEY: symbol;

export { AFTER_HOOK_KEY, AUTH_MODULE_OPTIONS_KEY, AfterHook, AllowAnonymous, AuthGuard, AuthModule, AuthService, BEFORE_HOOK_KEY, BeforeHook, HOOK_KEY, Hook, Optional, OptionalAuth, OrgRoles, Public, Roles, Session };
export type { Auth, AuthHookContext, BaseUserSession, UserSession };
