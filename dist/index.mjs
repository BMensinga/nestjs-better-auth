import { createParamDecorator, SetMetadata, ConfigurableModuleBuilder, Inject, Injectable, ForbiddenException, UnauthorizedException, Module, Logger } from '@nestjs/common';
import { Reflector, DiscoveryModule, ApplicationConfig, DiscoveryService, MetadataScanner, HttpAdapterHost, APP_GUARD } from '@nestjs/core';
import { fromNodeHeaders, toNodeHandler } from 'better-auth/node';
import { createAuthMiddleware } from 'better-auth/plugins';
import * as express from 'express';
import { normalizePath } from '@nestjs/common/utils/shared.utils.js';
import { mapToExcludeRoute } from '@nestjs/core/middleware/utils.js';

const BEFORE_HOOK_KEY = Symbol("BEFORE_HOOK");
const AFTER_HOOK_KEY = Symbol("AFTER_HOOK");
const HOOK_KEY = Symbol("HOOK");
const AUTH_MODULE_OPTIONS_KEY = Symbol("AUTH_MODULE_OPTIONS");

let GqlExecutionContext;
function getGqlExecutionContext() {
  if (!GqlExecutionContext) {
    GqlExecutionContext = require("@nestjs/graphql").GqlExecutionContext;
  }
  return GqlExecutionContext;
}
function getRequestFromContext(context) {
  const contextType = context.getType();
  if (contextType === "graphql") {
    return getGqlExecutionContext().create(context).getContext().req;
  }
  if (contextType === "ws") {
    return context.switchToWs().getClient();
  }
  return context.switchToHttp().getRequest();
}

const AllowAnonymous = () => SetMetadata("PUBLIC", true);
const OptionalAuth = () => SetMetadata("OPTIONAL", true);
const Roles = (roles) => SetMetadata("ROLES", roles);
const OrgRoles = (roles) => SetMetadata("ORG_ROLES", roles);
const Public = AllowAnonymous;
const Optional = OptionalAuth;
const Session = createParamDecorator((_data, context) => {
  const request = getRequestFromContext(context);
  return request.session;
});
const BeforeHook = (path) => SetMetadata(BEFORE_HOOK_KEY, path);
const AfterHook = (path) => SetMetadata(AFTER_HOOK_KEY, path);
const Hook = () => SetMetadata(HOOK_KEY, true);

const MODULE_OPTIONS_TOKEN = Symbol("AUTH_MODULE_OPTIONS");
const { ConfigurableModuleClass, OPTIONS_TYPE, ASYNC_OPTIONS_TYPE } = new ConfigurableModuleBuilder({
  optionsInjectionToken: MODULE_OPTIONS_TOKEN
}).setClassMethodName("forRoot").setExtras(
  {
    isGlobal: true,
    disableGlobalAuthGuard: false,
    disableControllers: false
  },
  (def, extras) => {
    return {
      ...def,
      exports: [MODULE_OPTIONS_TOKEN],
      global: extras.isGlobal
    };
  }
).build();

var __getOwnPropDesc$2 = Object.getOwnPropertyDescriptor;
var __decorateClass$2 = (decorators, target, key, kind) => {
  var result = kind > 1 ? void 0 : kind ? __getOwnPropDesc$2(target, key) : target;
  for (var i = decorators.length - 1, decorator; i >= 0; i--)
    if (decorator = decorators[i])
      result = (decorator(result)) || result;
  return result;
};
var __decorateParam$2 = (index, decorator) => (target, key) => decorator(target, key, index);
let AuthService = class {
  constructor(options) {
    this.options = options;
  }
  /**
   * Returns the API endpoints provided by the auth instance
   */
  get api() {
    return this.options.auth.api;
  }
  /**
   * Returns the complete auth instance
   * Access this for plugin-specific functionality
   */
  get instance() {
    return this.options.auth;
  }
};
AuthService = __decorateClass$2([
  __decorateParam$2(0, Inject(MODULE_OPTIONS_TOKEN))
], AuthService);

var __getOwnPropDesc$1 = Object.getOwnPropertyDescriptor;
var __decorateClass$1 = (decorators, target, key, kind) => {
  var result = kind > 1 ? void 0 : kind ? __getOwnPropDesc$1(target, key) : target;
  for (var i = decorators.length - 1, decorator; i >= 0; i--)
    if (decorator = decorators[i])
      result = (decorator(result)) || result;
  return result;
};
var __decorateParam$1 = (index, decorator) => (target, key) => decorator(target, key, index);
let GraphQLErrorClass;
function getGraphQLError() {
  if (!GraphQLErrorClass) {
    try {
      GraphQLErrorClass = require("graphql").GraphQLError;
    } catch (_error) {
      throw new Error(
        "graphql is required for GraphQL support. Please install it: npm install graphql"
      );
    }
  }
  return GraphQLErrorClass;
}
let WsException;
function getWsException() {
  if (!WsException) {
    try {
      WsException = require("@nestjs/websockets").WsException;
    } catch (_error) {
      throw new Error(
        "@nestjs/websockets is required for WebSocket support. Please install it: npm install @nestjs/websockets @nestjs/platform-socket.io"
      );
    }
  }
  return WsException;
}
const AuthContextErrorMap = {
  http: {
    UNAUTHORIZED: (args) => new UnauthorizedException(
      args ?? {
        code: "UNAUTHORIZED",
        message: "Unauthorized"
      }
    ),
    FORBIDDEN: (args) => new ForbiddenException(
      args ?? {
        code: "FORBIDDEN",
        message: "Insufficient permissions"
      }
    )
  },
  graphql: {
    UNAUTHORIZED: (args) => {
      const GraphQLError = getGraphQLError();
      if (typeof args === "string") {
        return new GraphQLError(args);
      } else if (typeof args === "object") {
        return new GraphQLError(
          // biome-ignore lint: if `message` is not set, a default is already in place.
          args?.message ?? "Unauthorized",
          args
        );
      }
      return new GraphQLError("Unauthorized");
    },
    FORBIDDEN: (args) => {
      const GraphQLError = getGraphQLError();
      if (typeof args === "string") {
        return new GraphQLError(args);
      } else if (typeof args === "object") {
        return new GraphQLError(
          // biome-ignore lint: if `message` is not set, a default is already in place.
          args?.message ?? "Forbidden",
          args
        );
      }
      return new GraphQLError("Forbidden");
    }
  },
  ws: {
    UNAUTHORIZED: (args) => {
      const WsExceptionClass = getWsException();
      return new WsExceptionClass(args ?? "UNAUTHORIZED");
    },
    FORBIDDEN: (args) => {
      const WsExceptionClass = getWsException();
      return new WsExceptionClass(args ?? "FORBIDDEN");
    }
  },
  rpc: {
    UNAUTHORIZED: () => new Error("UNAUTHORIZED"),
    FORBIDDEN: () => new Error("FORBIDDEN")
  }
};
let AuthGuard = class {
  constructor(reflector, options) {
    this.reflector = reflector;
    this.options = options;
  }
  /**
   * Validates if the current request is authenticated
   * Attaches session and user information to the request object
   * Supports HTTP, GraphQL and WebSocket execution contexts
   * @param context - The execution context of the current request
   * @returns True if the request is authorized to proceed, throws an error otherwise
   */
  async canActivate(context) {
    const request = getRequestFromContext(context);
    const session = await this.options.auth.api.getSession({
      headers: fromNodeHeaders(
        request.headers || request?.handshake?.headers || []
      )
    });
    request.session = session;
    request.user = session?.user ?? null;
    const isPublic = this.reflector.getAllAndOverride("PUBLIC", [
      context.getHandler(),
      context.getClass()
    ]);
    if (isPublic) return true;
    const isOptional = this.reflector.getAllAndOverride("OPTIONAL", [
      context.getHandler(),
      context.getClass()
    ]);
    if (!session && isOptional) return true;
    const ctxType = context.getType();
    if (!session) throw AuthContextErrorMap[ctxType].UNAUTHORIZED();
    const headers = fromNodeHeaders(
      request.headers || request?.handshake?.headers || []
    );
    const requiredRoles = this.reflector.getAllAndOverride("ROLES", [
      context.getHandler(),
      context.getClass()
    ]);
    if (requiredRoles && requiredRoles.length > 0) {
      const hasRole = this.checkUserRole(session, requiredRoles);
      if (!hasRole) throw AuthContextErrorMap[ctxType].FORBIDDEN();
    }
    const requiredOrgRoles = this.reflector.getAllAndOverride(
      "ORG_ROLES",
      [context.getHandler(), context.getClass()]
    );
    if (requiredOrgRoles && requiredOrgRoles.length > 0) {
      const hasOrgRole = await this.checkOrgRole(
        session,
        headers,
        requiredOrgRoles
      );
      if (!hasOrgRole) throw AuthContextErrorMap[ctxType].FORBIDDEN();
    }
    return true;
  }
  /**
   * Checks if a role value matches any of the required roles
   * Handles both array and comma-separated string role formats
   * @param role - The role value to check (string, array, or undefined)
   * @param requiredRoles - Array of roles that grant access
   * @returns True if the role matches any required role
   */
  matchesRequiredRole(role, requiredRoles) {
    if (!role) return false;
    if (Array.isArray(role)) {
      return role.some((r) => requiredRoles.includes(r));
    }
    if (typeof role === "string") {
      return role.split(",").some((r) => requiredRoles.includes(r.trim()));
    }
    return false;
  }
  /**
   * Fetches the user's role within an organization from the member table
   * Uses Better Auth's organization plugin API if available
   * @param headers - The request headers containing session cookies
   * @returns The member's role in the organization, or undefined if not found
   */
  async getMemberRoleInOrganization(headers) {
    try {
      const authApi = this.options.auth.api;
      if (typeof authApi.getActiveMemberRole === "function") {
        const result = await authApi.getActiveMemberRole({ headers });
        return result?.role;
      }
      if (typeof authApi.getActiveMember === "function") {
        const member = await authApi.getActiveMember({ headers });
        return member?.role;
      }
      return void 0;
    } catch (error) {
      throw error;
    }
  }
  /**
   * Checks if the user has any of the required roles in user.role only.
   * Used by @Roles() decorator for system-level role checks (admin plugin).
   * @param session - The user's session
   * @param requiredRoles - Array of roles that grant access
   * @returns True if user.role matches any required role
   */
  checkUserRole(session, requiredRoles) {
    return this.matchesRequiredRole(session.user.role, requiredRoles);
  }
  /**
   * Checks if the user has any of the required roles in their organization.
   * Used by @OrgRoles() decorator for organization-level role checks.
   * Requires an active organization in the session.
   * @param session - The user's session
   * @param headers - The request headers for API calls
   * @param requiredRoles - Array of roles that grant access
   * @returns True if org member role matches any required role
   */
  async checkOrgRole(session, headers, requiredRoles) {
    const activeOrgId = session.session?.activeOrganizationId;
    if (!activeOrgId) {
      return false;
    }
    try {
      const memberRole = await this.getMemberRoleInOrganization(headers);
      return this.matchesRequiredRole(memberRole, requiredRoles);
    } catch (error) {
      console.error("Organization plugin error:", error);
      return false;
    }
  }
};
AuthGuard = __decorateClass$1([
  Injectable(),
  __decorateParam$1(0, Inject(Reflector)),
  __decorateParam$1(1, Inject(MODULE_OPTIONS_TOKEN))
], AuthGuard);

const rawBodyParser = (req, _res, buffer) => {
  if (Buffer.isBuffer(buffer)) {
    req.rawBody = buffer;
  }
  return true;
};
function SkipBodyParsingMiddleware(options = {}) {
  const { basePath = "/api/auth", enableRawBodyParser = false } = options;
  const jsonParserOptions = enableRawBodyParser ? { verify: rawBodyParser } : {};
  return (req, res, next) => {
    if (req.baseUrl.startsWith(basePath)) {
      next();
      return;
    }
    express.json(jsonParserOptions)(req, res, (err) => {
      if (err) {
        next(err);
        return;
      }
      express.urlencoded({ extended: true })(req, res, next);
    });
  };
}

var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __decorateClass = (decorators, target, key, kind) => {
  var result = kind > 1 ? void 0 : kind ? __getOwnPropDesc(target, key) : target;
  for (var i = decorators.length - 1, decorator; i >= 0; i--)
    if (decorator = decorators[i])
      result = (decorator(result)) || result;
  return result;
};
var __decorateParam = (index, decorator) => (target, key) => decorator(target, key, index);
const HOOKS = [
  { metadataKey: BEFORE_HOOK_KEY, hookType: "before" },
  { metadataKey: AFTER_HOOK_KEY, hookType: "after" }
];
let AuthModule = class extends ConfigurableModuleClass {
  constructor(applicationConfig, discoveryService, metadataScanner, adapter, options) {
    super();
    this.applicationConfig = applicationConfig;
    this.discoveryService = discoveryService;
    this.metadataScanner = metadataScanner;
    this.adapter = adapter;
    this.options = options;
    this.basePath = normalizePath(
      this.options.auth.options.basePath ?? "/api/auth"
    );
    const globalPrefixOptions = this.applicationConfig.getGlobalPrefixOptions();
    this.applicationConfig.setGlobalPrefixOptions({
      exclude: [
        ...globalPrefixOptions.exclude ?? [],
        ...mapToExcludeRoute([this.basePath])
      ]
    });
  }
  logger = new Logger(AuthModule.name);
  basePath;
  onModuleInit() {
    const providers = this.discoveryService.getProviders().filter(
      ({ metatype }) => metatype && Reflect.getMetadata(HOOK_KEY, metatype)
    );
    const hasHookProviders = providers.length > 0;
    const hooksConfigured = typeof this.options.auth?.options?.hooks === "object";
    if (hasHookProviders && !hooksConfigured)
      throw new Error(
        "Detected @Hook providers but Better Auth 'hooks' are not configured. Add 'hooks: {}' to your betterAuth(...) options."
      );
    if (!hooksConfigured) return;
    for (const provider of providers) {
      const providerPrototype = Object.getPrototypeOf(provider.instance);
      const methods = this.metadataScanner.getAllMethodNames(providerPrototype);
      for (const method of methods) {
        const providerMethod = providerPrototype[method];
        this.setupHooks(providerMethod, provider.instance);
      }
    }
  }
  configure(consumer) {
    const trustedOrigins = this.options.auth.options.trustedOrigins;
    const isNotFunctionBased = trustedOrigins && Array.isArray(trustedOrigins);
    if (!this.options.disableTrustedOriginsCors && isNotFunctionBased) {
      this.adapter.httpAdapter.enableCors({
        origin: trustedOrigins,
        methods: ["GET", "POST", "PUT", "DELETE"],
        credentials: true
      });
    } else if (trustedOrigins && !this.options.disableTrustedOriginsCors && !isNotFunctionBased)
      throw new Error(
        "Function-based trustedOrigins not supported in NestJS. Use string array or disable CORS with disableTrustedOriginsCors: true."
      );
    if (!this.options.disableBodyParser) {
      consumer.apply(
        SkipBodyParsingMiddleware({
          basePath: this.basePath,
          enableRawBodyParser: this.options.enableRawBodyParser
        })
      ).forRoutes("*path");
    }
    const handler = toNodeHandler(this.options.auth);
    consumer.apply((req, res) => {
      if (this.options.middleware) {
        return this.options.middleware(req, res, () => handler(req, res));
      }
      return handler(req, res);
    }).forRoutes(this.basePath);
    this.logger.log(`AuthModule initialized BetterAuth on '${this.basePath}'`);
  }
  setupHooks(providerMethod, providerClass) {
    if (!this.options.auth.options.hooks) return;
    for (const { metadataKey, hookType } of HOOKS) {
      const hasHook = Reflect.hasMetadata(metadataKey, providerMethod);
      if (!hasHook) continue;
      const hookPath = Reflect.getMetadata(metadataKey, providerMethod);
      const originalHook = this.options.auth.options.hooks[hookType];
      this.options.auth.options.hooks[hookType] = createAuthMiddleware(
        async (ctx) => {
          if (originalHook) {
            await originalHook(ctx);
          }
          if (hookPath && hookPath !== ctx.path) return;
          await providerMethod.apply(providerClass, [ctx]);
        }
      );
    }
  }
  static forRootAsync(options) {
    const forRootAsyncResult = super.forRootAsync(options);
    const { module } = forRootAsyncResult;
    return {
      ...forRootAsyncResult,
      module: options.disableControllers ? AuthModuleWithoutControllers : module,
      controllers: options.disableControllers ? [] : forRootAsyncResult.controllers,
      providers: [
        ...forRootAsyncResult.providers ?? [],
        ...!options.disableGlobalAuthGuard ? [
          {
            provide: APP_GUARD,
            useClass: AuthGuard
          }
        ] : []
      ]
    };
  }
  static forRoot(arg1, arg2) {
    const normalizedOptions = typeof arg1 === "object" && arg1 !== null && "auth" in arg1 ? arg1 : { ...arg2 ?? {}, auth: arg1 };
    const forRootResult = super.forRoot(normalizedOptions);
    const { module } = forRootResult;
    return {
      ...forRootResult,
      module: normalizedOptions.disableControllers ? AuthModuleWithoutControllers : module,
      controllers: normalizedOptions.disableControllers ? [] : forRootResult.controllers,
      providers: [
        ...forRootResult.providers ?? [],
        ...!normalizedOptions.disableGlobalAuthGuard ? [
          {
            provide: APP_GUARD,
            useClass: AuthGuard
          }
        ] : []
      ]
    };
  }
};
AuthModule = __decorateClass([
  Module({
    imports: [DiscoveryModule],
    providers: [AuthService],
    exports: [AuthService]
  }),
  __decorateParam(0, Inject(ApplicationConfig)),
  __decorateParam(1, Inject(DiscoveryService)),
  __decorateParam(2, Inject(MetadataScanner)),
  __decorateParam(3, Inject(HttpAdapterHost)),
  __decorateParam(4, Inject(MODULE_OPTIONS_TOKEN))
], AuthModule);
class AuthModuleWithoutControllers extends AuthModule {
  configure() {
    return;
  }
}

export { AFTER_HOOK_KEY, AUTH_MODULE_OPTIONS_KEY, AfterHook, AllowAnonymous, AuthGuard, AuthModule, AuthService, BEFORE_HOOK_KEY, BeforeHook, HOOK_KEY, Hook, Optional, OptionalAuth, OrgRoles, Public, Roles, Session };
