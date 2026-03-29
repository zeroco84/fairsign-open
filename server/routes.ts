import type { Express, Request, Response, NextFunction } from "express";
import express from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { 
  getStorageBackend, 
  type IStorageBackend,
  createUserStorageBackend,
  type DropboxCredentials,
  type BoxCredentials,
  type CustomS3Credentials,
  getStorageBucketInfo,
  type DataRegion,
  getStorageBackendForRegion,
} from "./services/storageBackend";
import { decryptToken } from "./services/externalStorage";
import { createDocumentRequestSchema } from "@shared/schema";
import { renderHtmlToPdf, renderDocumentFromTemplate } from "./services/pdfRender";
import { stampSignaturesIntoPdf, appendAuditTrailPage } from "./services/pdfStamp";
import { sendWebhook } from "./services/webhook";
import { logAuditEvent } from "./services/audit";
import { 
  sendSignatureRequestEmail, 
  sendCompletionNoticeEmail, 
  sendCompletionEmailWithAttachment,
  sendReminderEmail,
  getEmailLogsForDocument 
} from "./services/emailService";
import { setupAuth, registerAuthRoutes, isAuthenticated } from "./replit_integrations/auth";
import { authStorage } from "./replit_integrations/auth/storage";
import { getTierLimits, isEnterprise, isProOrHigher } from "@shared/models/auth";
import { createFeatureAccessMiddleware } from "./middleware/feature-access";
import { createBearerAuthMiddleware } from "./middleware/bearer-auth";
import { nanoid } from "nanoid";
import { createHash } from "crypto";
import multer from "multer";
import { z } from "zod";

const upload = multer({ storage: multer.memoryStorage() });

// Helper to join paths without double slashes
function joinStoragePath(prefix: string, key: string): string {
  if (key.includes("..")) {
    throw new Error("Invalid path");
  }
  if (!prefix || prefix === "/" || prefix === "") {
    return key;
  }
  const cleanPrefix = prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
  const cleanKey = key.startsWith("/") ? key.slice(1) : key;
  return `${cleanPrefix}/${cleanKey}`;
}

// Configurable storage backend (Replit Object Storage or S3/R2)
let objectStorage: IStorageBackend;

// Helper function to check if a user can access documents from another user (team membership)
async function canAccessUserDocuments(currentUserId: string, documentOwnerId: string | null): Promise<boolean> {
  if (!documentOwnerId) return false;
  if (currentUserId === documentOwnerId) return true;
  
  // Check if both users are in the same organization
  const currentUser = await authStorage.getUser(currentUserId);
  const documentOwner = await authStorage.getUser(documentOwnerId);
  
  if (!currentUser?.organizationId || !documentOwner?.organizationId) {
    return false;
  }
  
  // Users are in the same organization
  return currentUser.organizationId === documentOwner.organizationId;
}

// Get all user IDs that the current user can access documents from (self + team members)
async function getAccessibleUserIds(userId: string): Promise<string[]> {
  const userIds = [userId];
  
  const user = await authStorage.getUser(userId);
  if (!user?.organizationId) {
    return userIds;
  }
  
  // Get all members in the same organization
  const members = await authStorage.getOrganizationMembers(user.organizationId);
  for (const member of members) {
    if (member.userId !== userId) {
      userIds.push(member.userId);
    }
  }
  
  return userIds;
}

// Resolve storage bucket and region for document creation
// Enterprise users use their dataRegion setting, others default to EU
// Returns both metadata (for DB storage) and the actual backend for uploading
async function resolveDocumentStorageContext(userId?: string): Promise<{ 
  storageBucket: string; 
  storageRegion: DataRegion;
  backend: IStorageBackend;
}> {
  const defaultRegion: DataRegion = "EU";
  
  if (!userId) {
    // API-based calls without user context default to EU
    const info = getStorageBucketInfo(defaultRegion);
    return { ...info, backend: getStorageBackendForRegion(defaultRegion) };
  }
  
  try {
    const user = await authStorage.getUser(userId);
    if (!user) {
      const info = getStorageBucketInfo(defaultRegion);
      return { ...info, backend: getStorageBackendForRegion(defaultRegion) };
    }
    
    // Only Enterprise users can use non-default regions
    if (user.accountType === "enterprise" && user.dataRegion) {
      const region = user.dataRegion as DataRegion;
      const info = getStorageBucketInfo(region);
      return { ...info, backend: getStorageBackendForRegion(region) };
    }
    
    // Free and Pro users always use EU
    const info = getStorageBucketInfo(defaultRegion);
    return { ...info, backend: getStorageBackendForRegion(defaultRegion) };
  } catch (error) {
    console.error("Error resolving storage context:", error);
    const info = getStorageBucketInfo(defaultRegion);
    return { ...info, backend: getStorageBackendForRegion(defaultRegion) };
  }
}

// Get user's preferred storage backend with loaded credentials
async function getUserStorageBackend(userId: string): Promise<{ backend: IStorageBackend; provider: string }> {
  const user = await authStorage.getUser(userId);
  const provider = user?.storageProvider || "fairsign";
  
  // For default storage, just return the global object storage
  if (provider === "fairsign") {
    return { backend: objectStorage, provider };
  }
  
  // Verify Pro or Enterprise status for custom storage providers
  const isPro = user?.accountType === "pro" || user?.accountType === "enterprise";
  if (!isPro) {
    console.log(`[Storage] User ${userId} has ${provider} selected but is not Pro/Enterprise, falling back to default`);
    return { backend: objectStorage, provider: "fairsign" };
  }
  
  // For custom S3, load and decrypt credentials
  if (provider === "custom_s3") {
    const s3Creds = await authStorage.getUserS3Credentials(userId);
    if (!s3Creds) {
      console.log(`[Storage] User ${userId} has custom_s3 selected but no credentials, falling back to default`);
      return { backend: objectStorage, provider: "fairsign" };
    }
    
    try {
      const customS3Credentials: CustomS3Credentials = {
        endpoint: decryptToken(s3Creds.endpoint, userId),
        bucket: decryptToken(s3Creds.bucket, userId),
        accessKeyId: decryptToken(s3Creds.accessKeyId, userId),
        secretAccessKey: decryptToken(s3Creds.secretAccessKey, userId),
        region: s3Creds.region ? decryptToken(s3Creds.region, userId) : undefined,
      };
      
      const backend = createUserStorageBackend(
        { userId, provider: "custom_s3" },
        customS3Credentials
      );
      return { backend, provider };
    } catch (error) {
      console.error(`[Storage] Failed to load custom S3 credentials for user ${userId}:`, error);
      return { backend: objectStorage, provider: "fairsign" };
    }
  }
  
  // For Dropbox, load and decrypt OAuth credentials
  if (provider === "dropbox") {
    const creds = await authStorage.getStorageCredentials(userId, "dropbox");
    if (!creds || !creds.accessTokenEncrypted) {
      console.log(`[Storage] User ${userId} has dropbox selected but no credentials, falling back to default`);
      return { backend: objectStorage, provider: "fairsign" };
    }
    
    try {
      const dropboxCredentials: DropboxCredentials = {
        accessToken: decryptToken(creds.accessTokenEncrypted, userId),
        refreshToken: creds.refreshTokenEncrypted ? decryptToken(creds.refreshTokenEncrypted, userId) : undefined,
        tokenExpiresAt: creds.tokenExpiresAt,
        // Callback to persist refreshed tokens
        onTokenRefresh: async (newAccessToken: string, expiresAt: Date) => {
          const { encryptToken } = await import("./services/externalStorage");
          await authStorage.saveStorageCredential({
            userId,
            provider: "dropbox",
            accessTokenEncrypted: encryptToken(newAccessToken, userId),
            refreshTokenEncrypted: creds.refreshTokenEncrypted, // Keep existing refresh token
            tokenExpiresAt: expiresAt,
            providerEmail: creds.providerEmail,
            isActive: true,
          });
          console.log(`[Storage] Refreshed Dropbox token for user ${userId}`);
        },
      };
      
      const backend = createUserStorageBackend(
        { userId, provider: "dropbox" },
        undefined, // no custom S3
        dropboxCredentials
      );
      return { backend, provider };
    } catch (error) {
      console.error(`[Storage] Failed to load Dropbox credentials for user ${userId}:`, error);
      return { backend: objectStorage, provider: "fairsign" };
    }
  }
  
  // For Box, load and decrypt OAuth credentials
  if (provider === "box") {
    const creds = await authStorage.getStorageCredentials(userId, "box");
    if (!creds || !creds.accessTokenEncrypted) {
      console.log(`[Storage] User ${userId} has box selected but no credentials, falling back to default`);
      return { backend: objectStorage, provider: "fairsign" };
    }
    
    try {
      const boxCredentials: BoxCredentials = {
        accessToken: decryptToken(creds.accessTokenEncrypted, userId),
        refreshToken: creds.refreshTokenEncrypted ? decryptToken(creds.refreshTokenEncrypted, userId) : undefined,
        tokenExpiresAt: creds.tokenExpiresAt,
        onTokenRefresh: async (newAccessToken: string, newRefreshToken: string | undefined, expiresAt: Date) => {
          const { encryptToken } = await import("./services/externalStorage");
          await authStorage.saveStorageCredential({
            userId,
            provider: "box",
            accessTokenEncrypted: encryptToken(newAccessToken, userId),
            // Box rotates refresh tokens - save the new one if provided
            refreshTokenEncrypted: newRefreshToken ? encryptToken(newRefreshToken, userId) : creds.refreshTokenEncrypted,
            tokenExpiresAt: expiresAt,
            providerEmail: creds.providerEmail,
            isActive: true,
          });
          console.log(`[Storage] Refreshed Box token for user ${userId}`);
        },
      };
      
      const backend = createUserStorageBackend(
        { userId, provider: "box" },
        undefined, // no custom S3
        undefined, // no Dropbox
        boxCredentials
      );
      return { backend, provider };
    } catch (error) {
      console.error(`[Storage] Failed to load Box credentials for user ${userId}:`, error);
      return { backend: objectStorage, provider: "fairsign" };
    }
  }
  
  // For other providers (Google Drive), fall back to default for now
  console.log(`[Storage] Provider ${provider} not yet implemented, falling back to default`);
  return { backend: objectStorage, provider: "fairsign" };
}

// Helper to check if a user can access a template (owner, default, or team member)
async function canAccessTemplate(userId: string, templateOwnerId: string | null, isDefault: boolean): Promise<boolean> {
  if (isDefault) return true;
  if (!templateOwnerId) return false;
  return canAccessUserDocuments(userId, templateOwnerId);
}

// BoldSign compatibility mode
const BOLDSIGN_COMPAT = process.env.WEBHOOK_COMPAT_MODE === "boldsign";
if (BOLDSIGN_COMPAT) {
  console.log("[BoldSign Compat] Compatibility mode enabled");
}

// Internal API key middleware for server-to-server calls
function validateInternalApiKey(req: Request, res: Response, next: NextFunction) {
  const internalApiKey = process.env.INTERNAL_API_KEY;
  if (!internalApiKey) {
    console.warn("[Security] INTERNAL_API_KEY not set - internal endpoints disabled");
    return res.status(503).json({ error: "Internal API not configured" });
  }

  const providedKey = req.headers["x-internal-api-key"] as string;
  if (!providedKey || providedKey !== internalApiKey) {
    return res.status(401).json({ error: "Invalid or missing internal API key" });
  }

  next();
}

// Middleware to validate signing token (supports both document-level and signer-level tokens)
async function validateToken(req: Request, res: Response, next: NextFunction) {
  const token = req.query.token as string;
  const documentId = req.params.id;

  if (!token) {
    return res.status(401).json({ error: "Token required" });
  }

  // First try to find document by ID
  let document = await storage.getDocument(documentId);
  
  // If not found by ID, try to find by the token in dataJson->token (for embedded signing URLs)
  if (!document) {
    document = await storage.getDocumentByDataJsonToken(token);
    if (document) {
      console.log(`[validateToken] Document found by dataJson token, ID: ${document.id}`);
    }
  }
  
  if (!document) {
    return res.status(404).json({ error: "Document not found" });
  }

  // Check document-level token first (single-signer or legacy)
  if (document.signingToken === token) {
    (req as any).document = document;
    (req as any).signer = null; // No specific signer
    return next();
  }

  // Check dataJson->token for embedded signing compatibility
  const dataJson = document.dataJson as Record<string, any> | null;
  if (dataJson?.token === token) {
    (req as any).document = document;
    (req as any).signer = null;
    return next();
  }

  // Check signer-specific token (multi-signer)
  const signers = await storage.getDocumentSigners(document.id);
  const signer = signers.find(s => s.token === token);
  
  if (signer) {
    (req as any).document = document;
    (req as any).signer = signer;
    return next();
  }

  // Also check for signer tokens stored in dataJson.signers (for embedded signing)
  if (dataJson?.signers) {
    const jsonSigner = (dataJson.signers as Array<{ token?: string; id?: string; name?: string; email?: string }>)
      .find(s => s.token === token);
    if (jsonSigner) {
      (req as any).document = document;
      (req as any).signer = {
        id: jsonSigner.id,
        name: jsonSigner.name,
        email: jsonSigner.email,
        token: jsonSigner.token,
        role: "signer",
        status: "pending",
      };
      return next();
    }
  }

  return res.status(401).json({ error: "Invalid token" });
}

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  // Initialize storage backend
  objectStorage = getStorageBackend();

  // CSP frame-ancestors middleware for iframe embedding (legacy env var based)
  const allowedFrameAncestors = process.env.ALLOWED_FRAME_ANCESTORS;
  if (allowedFrameAncestors) {
    const ancestors = allowedFrameAncestors.split(",").map(s => s.trim()).filter(Boolean);
    console.log(`[BoldSign Compat] Frame embedding allowed from: ${ancestors.join(", ")}`);
    
    app.use((req, res, next) => {
      // Only apply to signing pages and API routes
      if (req.path.startsWith("/d/") || req.path.startsWith("/sign/") || req.path.startsWith("/api/")) {
        res.setHeader(
          "Content-Security-Policy",
          `frame-ancestors 'self' ${ancestors.join(" ")}`
        );
        res.setHeader("X-Frame-Options", "ALLOW-FROM " + ancestors[0]);
      }
      next();
    });
  }
  
  // Dynamic CSP middleware for embedded signing documents (Enterprise feature)
  // This sets frame-ancestors based on the document owner's allowedOrigins
  // For embedded documents, this OVERRIDES the legacy env var middleware
  app.use("/d/:documentId", async (req, res, next) => {
    const documentId = req.params.documentId;
    try {
      const document = await storage.getDocument(documentId);
      if (!document) {
        return next();
      }
      
      const dataJson = document.dataJson as Record<string, any> | null;
      const isEmbeddedDoc = dataJson?.embeddedSigning === true;
      
      if (isEmbeddedDoc && document.userId) {
        // Embedded documents ALWAYS use document-level CSP (overrides env var)
        const owner = await authStorage.getUser(document.userId);
        const allowedOrigins = owner?.allowedOrigins || [];
        
        if (allowedOrigins.length > 0) {
          // Allow embedding from configured origins only
          res.setHeader("Content-Security-Policy", `frame-ancestors 'self' ${allowedOrigins.join(" ")}`);
          res.setHeader("X-Frame-Options", `ALLOW-FROM ${allowedOrigins[0]}`);
        } else {
          // Embedded doc but no origins configured - block embedding
          res.setHeader("Content-Security-Policy", "frame-ancestors 'self'");
          res.setHeader("X-Frame-Options", "SAMEORIGIN");
        }
      } else if (!allowedFrameAncestors) {
        // Regular signing page without env var config - deny framing
        res.setHeader("Content-Security-Policy", "frame-ancestors 'self'");
        res.setHeader("X-Frame-Options", "SAMEORIGIN");
      }
      // If env var is set AND not an embedded doc, the previous middleware already set CSP
    } catch (error) {
      console.error("[CSP Middleware] Error checking document for CSP:", error);
    }
    next();
  });

  // Setup authentication (must be before other routes)
  await setupAuth(app);
  registerAuthRoutes(app);
  
  // Apply bearer auth middleware to support API key authentication
  // This must be AFTER session setup so req.session exists
  const bearerAuth = createBearerAuthMiddleware(authStorage);
  app.use(bearerAuth);
  
  // Create feature access middleware for tier-gated features
  const checkFeatureAccess = createFeatureAccessMiddleware(authStorage);

  // Seed signature spots (default templates removed - users create their own)
  await seedSignatureSpots();

  // Health check endpoint
  app.get("/health", (_req: Request, res: Response) => {
    res.status(200).json({ ok: true });
  });

  // Fallback subscription status endpoint (used when Stripe is not configured)
  // This endpoint is overridden by the EE payments module when Stripe is configured
  app.get("/api/subscription/status", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const user = await authStorage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Return subscription status from database (works without Stripe)
      res.json({
        accountType: user.accountType || "free",
        subscriptionStatus: user.subscriptionStatus || null,
        currentPeriodEnd: user.subscriptionCurrentPeriodEnd || null,
        documentsUsed: parseInt(user.documentsThisMonth || "0", 10),
        documentLimit: user.accountType === "pro" ? -1 : 5,
        canCreateDocument: user.accountType === "pro" || parseInt(user.documentsThisMonth || "0", 10) < 5,
      });
    } catch (error) {
      console.error("Error getting subscription status:", error);
      res.status(500).json({ error: "Failed to get subscription status" });
    }
  });

  // Create a new document
  app.post("/api/documents", async (req: Request, res: Response) => {
    try {
      const parseResult = createDocumentRequestSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({
          error: "Invalid request",
          details: parseResult.error.errors,
        });
      }

      const { template_id, data, callback_url, signers } = parseResult.data;

      // Generate document-level signing token (for single-signer backward compatibility)
      const signingToken = nanoid(32);

      // Render document from template (supports both HTML and PDF templates)
      console.log(`Rendering document from template: ${template_id}`);
      const pdfBuffer = await renderDocumentFromTemplate(template_id, data);

      // Calculate SHA-256 hash of the original rendered PDF before any modifications
      const originalHash = createHash("sha256").update(pdfBuffer).digest("hex");

      // Get storage context (API calls without user context default to EU)
      const storageContext = await resolveDocumentStorageContext();

      // Upload unsigned PDF to region-specific storage backend
      const unsignedPdfKey = `documents/${nanoid()}/unsigned.pdf`;
      await storageContext.backend.uploadBuffer(pdfBuffer, unsignedPdfKey, "application/pdf");
      console.log(`Uploaded unsigned PDF: ${unsignedPdfKey} to ${storageContext.storageRegion} region`);

      // Create document record with storage bucket info
      const document = await storage.createDocument({
        templateId: template_id,
        status: "created",
        dataJson: data,
        callbackUrl: callback_url || null,
        signingToken,
        unsignedPdfKey,
        signedPdfKey: null,
        signedPdfSha256: null,
        originalHash, // SHA-256 hash of original PDF before modifications
        storageBucket: storageContext.storageBucket,
        storageRegion: storageContext.storageRegion,
      });

      // Log audit event
      await logAuditEvent(document.id, "document_created", req, { template_id });

      const baseUrl = process.env.BASE_URL || `https://${req.headers.host}`;

      // Handle multi-signer case
      if (signers && signers.length > 0) {
        const signerLinks: Array<{ email: string; name: string; role: string; signLink: string }> = [];
        
        for (const signer of signers) {
          const signerToken = nanoid(32);
          await storage.createDocumentSigner({
            documentId: document.id,
            email: signer.email,
            name: signer.name,
            role: signer.role,
            token: signerToken,
            status: "pending",
          });

          const signLink = `${baseUrl}/d/${document.id}?token=${signerToken}`;
          signerLinks.push({
            email: signer.email,
            name: signer.name,
            role: signer.role,
            signLink,
          });

          await logAuditEvent(document.id, "signer_added", req, { 
            signerEmail: signer.email, 
            signerRole: signer.role 
          });
        }

        console.log(`Document created: ${document.id} with ${signers.length} signers`);

        res.status(201).json({
          document_id: document.id,
          documentId: document.id,
          signers: signerLinks,
          status: "created",
        });
      } else {
        // Single-signer backward compatibility
        const signingUrl = `${baseUrl}/d/${document.id}?token=${signingToken}`;

        console.log(`Document created: ${document.id}`);
        console.log(`Signing URL: ${signingUrl}`);

        res.status(201).json({
          // Original fields
          document_id: document.id,
          signing_url: signingUrl,
          // BoldSign-compatible aliases
          documentId: document.id,
          signLink: signingUrl,
        });
      }
    } catch (error) {
      console.error("Error creating document:", error);
      res.status(500).json({ error: "Failed to create document" });
    }
  });

  // Get document metadata for signing
  app.get("/api/documents/:id", validateToken, async (req: Request, res: Response) => {
    try {
      const document = (req as any).document;
      const signer = (req as any).signer;

      // Get document title from dataJson for one-off documents
      const dataJson = document.dataJson as Record<string, any> | null;
      const isOneOff = dataJson?.oneOffDocument === true;
      const documentTitle = dataJson?.title || "Document";

      // Get signature spots - handle one-off documents differently
      let spots: Array<{
        id: string;
        spotKey: string;
        kind: string;
        page: number;
        x: number;
        y: number;
        w: number;
        h: number;
        role?: string;
        placeholder?: string;
        inputMode?: string;
      }>;

      // Track which spots belong to this signer (for signing, not display)
      let requiredSpotKeys: string[] = [];

      if (isOneOff && dataJson?.fields) {
        // One-off document: convert ALL fields from dataJson to spots format
        const allFields = dataJson.fields as Array<{
          id: string;
          fieldType: string;
          signerId: string;
          page: number;
          x: number;
          y: number;
          width: number;
          height: number;
          creatorFills?: boolean;
          placeholder?: string;
          inputMode?: string;
          isDocumentDate?: boolean;
        }>;

        // Include ALL spots for rendering (including creatorFills for visual context)
        // Preserve fieldType as kind to support text, date, checkbox fields
        spots = allFields.map(field => ({
          id: field.id,
          spotKey: field.id,
          kind: field.fieldType, // text | signature | initial | date | checkbox
          page: field.page,
          x: field.x,
          y: field.y,
          w: field.width,
          h: field.height,
          role: field.signerId,
          creatorFills: field.creatorFills || false, // Pass through for UI rendering
          placeholder: field.placeholder, // Pass placeholder text for text/date fields
          inputMode: field.inputMode, // Pass input mode (numeric, text, any)
          isDocumentDate: field.isDocumentDate || false, // Auto-fill with signing date
        }));

        // Track only non-creatorFills spots this signer needs to complete
        const signerFields = allFields.filter(f => !f.creatorFills);
        if (signer) {
          requiredSpotKeys = signerFields
            .filter(f => f.signerId === signer.role)
            .map(f => f.id);
        } else {
          requiredSpotKeys = signerFields.map(f => f.id);
        }
      } else if (signer) {
        // Template-based multi-signer: get all spots but track which are for this signer
        spots = await storage.getSignatureSpots(document.templateId);
        const signerSpots = await storage.getSignatureSpotsByRole(document.templateId, signer.role);
        requiredSpotKeys = signerSpots.map(s => s.spotKey);
      } else {
        // Template-based single-signer: show all spots
        spots = await storage.getSignatureSpots(document.templateId);
        requiredSpotKeys = spots.map(s => s.spotKey);
      }

      // Get uploaded signature assets (all for the document)
      const assets = await storage.getSignatureAssets(document.id);
      const signingToken = req.query.token as string;
      
      // For the counter, only include spots signed by THIS signer (by signerRole)
      const uploadedSpots = signer
        ? assets.filter(a => a.signerRole === signer.role).map(a => a.spotKey)
        : assets.map(a => a.spotKey);
      
      // Build signature image URLs for ALL uploaded signatures (to show previous signers' signatures)
      // All signatures are visible to current signer - this allows seeing prior completed signatures
      // Use Object.create(null) to prevent prototype pollution when using dynamic keys
      const signatureImages: Record<string, string> = Object.create(null);
      for (const asset of assets) {
        signatureImages[asset.spotKey] = `/api/documents/${document.id}/signature-image/${asset.spotKey}?token=${signingToken}`;
      }

      // Use proxy URL instead of presigned URL to avoid CORS issues
      const unsignedPdfUrl = `/api/documents/${document.id}/unsigned.pdf?token=${signingToken}`;

      // Log view event
      await logAuditEvent(document.id, "document_viewed", req, {
        signerEmail: signer?.email,
        signerName: signer?.name,
        signerRole: signer?.role,
      });

      // Get all signers for status display (multi-signer mode)
      const allSigners = signer ? await storage.getDocumentSigners(document.id) : [];

      // Get text field values for one-off documents
      // Use Object.create(null) to prevent prototype pollution when using dynamic keys
      let textValues: Record<string, string> = Object.create(null);
      if (isOneOff) {
        const textFieldValuesList = await storage.getTextFieldValues(document.id);
        for (const tfv of textFieldValuesList) {
          textValues[tfv.spotKey] = tfv.value;
          // Also mark text field spots as uploaded
          if (!uploadedSpots.includes(tfv.spotKey)) {
            uploadedSpots.push(tfv.spotKey);
          }
        }
      }

      // Check if document owner has verified identity and get allowed origins for CSP
      let senderVerified = false;
      let allowedOrigins: string[] = [];
      if (document.userId) {
        const owner = await authStorage.getUser(document.userId);
        senderVerified = !!owner?.identityVerifiedAt;
        allowedOrigins = owner?.allowedOrigins || [];
      }
      
      // Set Content-Security-Policy frame-ancestors header for embedded signing security
      // If document is marked as embedded signing AND owner has allowed origins, use those
      // Otherwise, block all iframe embedding
      const isEmbeddedDoc = dataJson?.embeddedSigning === true;
      if (isEmbeddedDoc && allowedOrigins.length > 0) {
        // Allow embedding from configured origins
        res.setHeader("Content-Security-Policy", `frame-ancestors 'self' ${allowedOrigins.join(" ")}`);
      } else if (isEmbeddedDoc) {
        // Embedded doc but no origins configured - block embedding
        res.setHeader("Content-Security-Policy", "frame-ancestors 'self'");
      } else {
        // Regular signing page - allow embedding from anywhere for backward compatibility
        // Users can still access via direct link
      }

      // Extract embedded signing info for parent frame communication
      const embeddedRedirectUrl = isEmbeddedDoc ? dataJson?.redirectUrl || null : null;

      res.json({
        id: document.id,
        templateId: document.templateId,
        status: document.status,
        title: documentTitle,
        unsignedPdfUrl,
        spots, // All spots for rendering (includes all signers)
        requiredSpotKeys, // Spot keys this signer needs to sign
        uploadedSpots, // Spots already signed/filled by this signer (for counter)
        signatureImages, // Map of spotKey -> image URL for rendering on PDF
        textValues, // Map of spotKey -> text value for text/date/checkbox fields
        signerId: signer?.id || null, // The ID of the current signer (for mobile signing sessions)
        senderVerified, // Whether document owner has verified identity
        // Embedded signing info for postMessage communication
        embeddedSigning: isEmbeddedDoc,
        embeddedRedirectUrl, // Redirect URL after signing (for embedded docs)
        allowedOrigins: isEmbeddedDoc ? allowedOrigins : [], // For secure postMessage targeting
        currentSigner: signer ? {
          email: signer.email,
          name: signer.name,
          role: signer.role,
          status: signer.status,
        } : null,
        signers: allSigners.map(s => ({
          email: s.email,
          name: s.name,
          role: s.role,
          status: s.status,
        })),
      });
    } catch (error) {
      console.error("Error getting document:", error);
      res.status(500).json({ error: "Failed to get document" });
    }
  });

  // Upload a signature or initial
  app.post(
    "/api/documents/:id/signatures",
    validateToken,
    upload.single("image"),
    async (req: Request, res: Response) => {
      try {
        const document = (req as any).document;
        const signer = (req as any).signer;
        const spotKey = req.body.spot_key;
        const file = req.file;

        if (!spotKey) {
          return res.status(400).json({ error: "spot_key required" });
        }

        if (!file) {
          return res.status(400).json({ error: "image file required" });
        }

        if (document.status === "completed") {
          return res.status(400).json({ error: "Document already completed" });
        }

        // Verify spot exists - check dataJson for one-off documents, otherwise signature_spots table
        let spotRole: string | null = null;
        const docData = document.dataJson as Record<string, any> | null;
        
        if (docData?.oneOffDocument && docData.fields) {
          // One-off document: look up spot in dataJson.fields
          const field = (docData.fields as Array<{ id: string; signerId: string }>)
            .find(f => f.id === spotKey);
          if (!field) {
            return res.status(400).json({ error: "Invalid spot_key" });
          }
          spotRole = field.signerId;
        } else {
          // Template-based document: look up spot in signature_spots table
          const spot = await storage.getSignatureSpot(document.templateId, spotKey);
          if (!spot) {
            return res.status(400).json({ error: "Invalid spot_key" });
          }
          spotRole = spot.signerRole;
        }

        // Multi-signer: verify this signer is allowed to sign this spot
        if (signer && spotRole !== signer.role) {
          return res.status(403).json({ 
            error: "This signature spot is not assigned to you",
            yourRole: signer.role,
            spotRole: spotRole,
          });
        }

        // Check if already uploaded
        const existing = await storage.getSignatureAsset(document.id, spotKey);
        if (existing) {
          return res.status(400).json({ error: "Signature already uploaded for this spot" });
        }

        // Upload signature image to object storage
        const imageKey = `documents/${document.id}/signatures/${spotKey}.png`;
        await objectStorage.uploadBuffer(file.buffer, imageKey, "image/png");

        // Create signature asset record (with signer info if multi-signer)
        await storage.createSignatureAsset({
          documentId: document.id,
          spotKey,
          imageKey,
          signerRole: signer?.role || null,
          signerEmail: signer?.email || null,
        });

        // Log audit event
        await logAuditEvent(document.id, "signature_uploaded", req, { 
          spotKey,
          signerEmail: signer?.email,
          signerName: signer?.name,
          signerRole: signer?.role,
        });

        console.log(`Signature uploaded: ${spotKey} for document ${document.id}${signer ? ` by ${signer.email}` : ""}`);

        res.status(201).json({ success: true, spotKey });
      } catch (error) {
        console.error("Error uploading signature:", error);
        res.status(500).json({ error: "Failed to upload signature" });
      }
    }
  );

  // Submit a text field value (for text, date, checkbox fields)
  app.post(
    "/api/documents/:id/text-field",
    validateToken,
    async (req: Request, res: Response) => {
      try {
        const document = (req as any).document;
        const signer = (req as any).signer;
        const { spotKey, value, apiTag } = req.body;

        if ((!spotKey && !apiTag) || value === undefined) {
          return res.status(400).json({ error: "spotKey (or apiTag) and value are required" });
        }

        if (document.status === "completed") {
          return res.status(400).json({ error: "Document already completed" });
        }

        // Verify spot exists and is a text/date/checkbox field
        const docData = document.dataJson as Record<string, any> | null;
        let field: { id: string; signerId?: string; fieldType: string; apiTag?: string } | undefined;
        let effectiveSpotKey = spotKey;

        // Strategy 1: One-off document fields
        if (docData?.oneOffDocument && docData.fields) {
          if (spotKey) {
            field = (docData.fields as any[]).find(f => f.id === spotKey);
          } else if (apiTag) {
            field = (docData.fields as any[]).find(f => f.apiTag === apiTag);
            if (field) effectiveSpotKey = field.id;
          }
        } 
        
        // Strategy 2: Template fields (from DB) if not found yet
        if (!field && document.templateId) {
          const templateFields = await storage.getTemplateFields(document.templateId);
          if (spotKey) {
            // Note: templateFields use 'id' as the unique identifier which maps to spotKey
            field = templateFields.find(f => f.id === spotKey);
          } else if (apiTag) {
            field = templateFields.find(f => f.apiTag === apiTag);
            if (field) effectiveSpotKey = field.id;
          }
        }
        
        if (!field) {
          return res.status(400).json({ error: "Invalid spotKey or apiTag" });
        }

        // Map signerRole from template field (it might be called signerRole or signerId depending on source)
        const fieldSignerRole = field.signerId || (field as any).signerRole;

        if (!["text", "date", "checkbox"].includes(field.fieldType)) {
          return res.status(400).json({ error: "This spot is not a text field" });
        }

        // Multi-signer: verify this signer is allowed to fill this field
        if (signer && fieldSignerRole && fieldSignerRole !== signer.role) {
          return res.status(403).json({ 
            error: "This field is not assigned to you",
            yourRole: signer.role,
            fieldRole: fieldSignerRole,
          });
        }

        // Use the ID as the spotKey for storage consistency
        if (!effectiveSpotKey) effectiveSpotKey = field.id;

        // Check if already filled
        const existingValues = await storage.getTextFieldValues(document.id);
        const existing = existingValues.find(v => v.spotKey === effectiveSpotKey);
        if (existing) {
          return res.status(400).json({ error: "Value already submitted for this field" });
        }

        // Create text field value record
        await storage.createTextFieldValue({
          documentId: document.id,
          spotKey: effectiveSpotKey,
          value,
          fieldType: field.fieldType,
          signerRole: signer?.role || null,
          signerEmail: signer?.email || null,
        });

        // Log audit event
        await logAuditEvent(document.id, "text_field_submitted", req, { 
          spotKey: effectiveSpotKey,
          fieldType: field.fieldType,
          signerEmail: signer?.email,
          signerRole: signer?.role,
        });

        console.log(`Text field submitted: ${effectiveSpotKey} for document ${document.id}${signer ? ` by ${signer.email}` : ""}`);

        res.status(201).json({ success: true, spotKey: effectiveSpotKey });
      } catch (error) {
        console.error("Error submitting text field:", error);
        res.status(500).json({ error: "Failed to submit text field" });
      }
    }
  );

  // Complete document signing (supports both single-signer and multi-signer modes)
  app.post("/api/documents/:id/complete", validateToken, async (req: Request, res: Response) => {
    try {
      const document = (req as any).document;
      const signer = (req as any).signer;

      if (document.status === "completed") {
        return res.status(400).json({ error: "Document already completed" });
      }

      // Check consent
      if (!req.body.consent) {
        return res.status(400).json({ error: "Consent required" });
      }

      // Multi-signer: check if this signer already completed
      if (signer && signer.status === "completed") {
        return res.status(400).json({ error: "You have already signed this document" });
      }

      // Get spots for verification (role-specific for multi-signer)
      let spotsToVerify: Array<{ spotKey: string }>;
      const docData = document.dataJson as Record<string, any> | null;
      
      if (docData?.oneOffDocument && docData.fields) {
        // One-off document: get spots from dataJson.fields
        const allFields = docData.fields as Array<{ id: string; signerId: string }>;
        const relevantFields = signer 
          ? allFields.filter(f => f.signerId === signer.role)
          : allFields;
        spotsToVerify = relevantFields.map(f => ({ spotKey: f.id }));
      } else if (signer) {
        spotsToVerify = await storage.getSignatureSpotsByRole(document.templateId, signer.role);
      } else {
        spotsToVerify = await storage.getSignatureSpots(document.templateId);
      }

      // Get uploaded signatures
      const assets = await storage.getSignatureAssets(document.id);
      const uploadedSpotKeys = new Set(assets.map((a) => a.spotKey));

      // Also get text field values (for text, date, checkbox fields)
      const completedTextFields = await storage.getTextFieldValues(document.id);
      for (const tfv of completedTextFields) {
        uploadedSpotKeys.add(tfv.spotKey);
      }

      // Verify required spots for this signer are signed/filled
      const missingSpots = spotsToVerify.filter((s) => !uploadedSpotKeys.has(s.spotKey));
      if (missingSpots.length > 0) {
        return res.status(400).json({
          error: "Missing signatures",
          missing: missingSpots.map((s) => s.spotKey),
        });
      }

      // Log consent
      await logAuditEvent(document.id, "consent_given", req, {
        signerEmail: signer?.email,
        signerName: signer?.name,
        signerRole: signer?.role,
      });

      // Multi-signer: mark this signer as completed and check if all done
      if (signer) {
        await storage.updateDocumentSigner(signer.id, {
          status: "completed",
          signedAt: new Date(),
        });

        await logAuditEvent(document.id, "signer_completed", req, {
          signerEmail: signer.email,
          signerName: signer.name,
          signerRole: signer.role,
        });

        console.log(`Signer ${signer.email} (${signer.role}) completed for document ${document.id}`);

        // Send "Signed" webhook for this signer (BoldSign compat)
        if (document.callbackUrl && BOLDSIGN_COMPAT) {
          const signedWebhook = {
            event: "Signed",
            documentId: document.id,
            signerEmail: signer.email,
            signerName: signer.name,
            signerRole: signer.role,
          };
          await sendWebhook(document.callbackUrl, signedWebhook);
          await logAuditEvent(document.id, "signer_webhook_sent", req, {
            signerEmail: signer.email,
            event: "Signed",
          });
        }

        // Check if all signers completed (signers are ordered by orderIndex)
        const allSigners = await storage.getDocumentSigners(document.id);
        const allCompleted = allSigners.every(s => s.status === "completed");

        if (!allCompleted) {
          // Find the next pending signer in order and notify them
          const pendingSigners = allSigners.filter(s => s.status !== "completed");
          const nextSigner = pendingSigners[0]; // First pending signer (lowest orderIndex)
          const docData = document.dataJson as Record<string, any> | null;
          
          // Only send email to next signer if this is a one-off document (sequential signing)
          // and the signer has valid email and token
          if (nextSigner && docData?.oneOffDocument && nextSigner.email && nextSigner.token) {
            // Send email to next signer in sequence
            try {
              const baseUrl = process.env.BASE_URL || `https://${req.headers.host}`;
              const signLink = `${baseUrl}/d/${document.id}?token=${nextSigner.token}`;
              const documentTitle = docData?.title || docData?.tenant_name || "Document";
              
              // Check if document owner is identity verified and get sender name
              let senderVerified = false;
              let senderName: string | undefined;
              if (document.userId) {
                const owner = await authStorage.getUser(document.userId);
                senderVerified = !!owner?.identityVerifiedAt;
                senderName = owner ? `${owner.firstName || ''} ${owner.lastName || ''}`.trim() || owner.email : undefined;
              }
              
              const { sendSignatureRequestEmailWithUrl } = await import("./services/emailService");
              await sendSignatureRequestEmailWithUrl(
                document.id,
                nextSigner.email,
                nextSigner.name,
                signLink,
                documentTitle,
                senderVerified,
                senderName
              );
              
              console.log(`[Sequential] Email sent to next signer: ${nextSigner.email} (order: ${nextSigner.orderIndex ?? 'N/A'})`);
              
              await logAuditEvent(document.id, "next_signer_notified", req, {
                signerEmail: nextSigner.email,
                signerName: nextSigner.name,
                signerRole: nextSigner.role,
                orderIndex: nextSigner.orderIndex ?? 0,
              });
            } catch (emailError) {
              console.error(`[Sequential] Failed to send email to next signer ${nextSigner.email}:`, emailError);
            }
          }
          
          // Not all signers done - return partial completion response
          return res.json({
            success: true,
            document_id: document.id,
            status: "partial",
            message: "Your signature has been recorded. Waiting for other signers.",
            pendingSigners: pendingSigners.map(s => s.email),
          });
        }

        console.log(`All signers completed for document ${document.id} - finalizing PDF`);
      }

      // All signers completed (or single-signer) - stamp and finalize PDF
      const dataJson = document.dataJson as Record<string, any> | null;
      const isOneOff = dataJson?.oneOffDocument === true;

      // Get spots - handle one-off documents differently
      let allSpots: Array<{
        id: string;
        spotKey: string;
        page: number;
        x: number;
        y: number;
        w: number;
        h: number;
        kind: string;
      }>;

      if (isOneOff && dataJson?.fields) {
        // One-off document: use fields from dataJson, preserving fieldType
        allSpots = (dataJson.fields as Array<{
          id: string;
          fieldType: string;
          page: number;
          x: number;
          y: number;
          width: number;
          height: number;
        }>).map(field => ({
          id: field.id,
          spotKey: field.id,
          page: field.page,
          x: field.x,
          y: field.y,
          w: field.width,
          h: field.height,
          kind: field.fieldType, // Preserve full fieldType for text/date/checkbox
        }));
      } else {
        // Template-based: get from signature_spots table
        const signatureSpots = await storage.getSignatureSpots(document.templateId);
        
        // Also get template fields (text/date/checkbox) to support stamping them
        const templateFields = await storage.getTemplateFields(document.templateId);
        
        // Map template fields to the spot format expected by stampSignaturesIntoPdf
        const fieldSpots = templateFields.map(tf => ({
          id: tf.id,
          spotKey: tf.id, // Use ID as spotKey for consistency with text-field upload
          page: tf.page,
          x: Number(tf.x),
          y: Number(tf.y),
          w: Number(tf.width),
          h: Number(tf.height),
          kind: tf.fieldType,
        }));
        
        allSpots = [...signatureSpots, ...fieldSpots];
      }

      const allAssets = await storage.getSignatureAssets(document.id);
      
      // Get text field values for all documents (one-off AND template-based)
      // We always fetch them because template-based docs can now have text updates too
      let textFieldValues: Array<{ spotKey: string; value: string; fieldType: string }> = await storage.getTextFieldValues(document.id);
      if (textFieldValues.length > 0) {
        console.log(`Found ${textFieldValues.length} text field values to stamp`);
      }

      // Download unsigned PDF
      const privateDir = objectStorage.getPrivateObjectDir();
      const unsignedPath = joinStoragePath(privateDir, document.unsignedPdfKey);
      const unsignedPdfBuffer = await objectStorage.downloadBuffer(unsignedPath);

      // Download all signature images with signed dates
      const signatures = await Promise.all(
        allAssets.map(async (asset) => {
          const imagePath = joinStoragePath(privateDir, asset.imageKey);
          const imageBuffer = await objectStorage.downloadBuffer(imagePath);
          return {
            spotKey: asset.spotKey,
            imageBuffer,
            signedAt: asset.createdAt,
          };
        })
      );

      // Stamp signatures and text fields into PDF
      console.log("Stamping signatures and text fields into PDF...");
      const stampedPdfBuffer = await stampSignaturesIntoPdf(
        unsignedPdfBuffer,
        allSpots,
        signatures,
        textFieldValues
      );

      // Calculate SHA-256 hash of stamped PDF (before audit trail)
      const sha256 = createHash("sha256").update(stampedPdfBuffer).digest("hex");

      // Check if document owner is identity verified for audit trail and get sender info
      let ownerVerified = false;
      let senderName: string | undefined;
      let senderEmail: string | undefined;
      if (document.userId) {
        const owner = await authStorage.getUser(document.userId);
        ownerVerified = !!owner?.identityVerifiedAt;
        senderEmail = owner?.email;
        senderName = owner ? `${owner.firstName || ''} ${owner.lastName || ''}`.trim() || undefined : undefined;
      }

      // Get audit events and append audit trail page
      const auditEvents = await storage.getAuditEvents(document.id);
      const signedPdfBuffer = await appendAuditTrailPage(stampedPdfBuffer, auditEvents, {
        documentId: document.id,
        documentTitle: docData?.title || docData?.tenant_name || undefined,
        sha256,
        originalHash: document.originalHash || undefined, // Use pre-signing hash for third-party verification
        senderVerified: ownerVerified,
        senderName,
        senderEmail,
      });

      // Upload signed PDF to user's preferred storage
      const signedPdfKey = `documents/${document.id}/signed.pdf`;
      
      // Get document owner's storage backend
      const { backend: userStorage, provider: storageProvider } = await getUserStorageBackend(document.userId);
      
      // For external storage (Dropbox, etc), use a flat folder structure with document title
      // Format: /FairSign/{document_title}_{shortId}_signed.pdf
      const safeDocTitle = (docData?.title || "Document").replace(/[^a-zA-Z0-9\-_\s]/g, "").trim();
      const externalStorageKey = `${safeDocTitle}_${document.id.slice(0, 8)}_signed.pdf`;
      
      try {
        if (storageProvider !== "fairsign") {
          // External storage uses flat folder with document title
          await userStorage.uploadBuffer(signedPdfBuffer, externalStorageKey, "application/pdf");
          console.log(`[Storage] Uploaded signed PDF to ${storageProvider}: ${externalStorageKey}`);
        } else {
          await userStorage.uploadBuffer(signedPdfBuffer, signedPdfKey, "application/pdf");
          console.log(`[Storage] Uploaded signed PDF to ${storageProvider}: ${signedPdfKey}`);
        }
      } catch (uploadError) {
        console.error(`[Storage] Failed to upload to ${storageProvider}, falling back to default:`, uploadError);
        // Fallback to default storage if user storage fails
        await objectStorage.uploadBuffer(signedPdfBuffer, signedPdfKey, "application/pdf");
        console.log(`[Storage] Uploaded signed PDF to default storage: ${signedPdfKey}`);
      }
      
      // Also always store in default storage for backup/access
      if (storageProvider !== "fairsign") {
        try {
          await objectStorage.uploadBuffer(signedPdfBuffer, signedPdfKey, "application/pdf");
          console.log(`[Storage] Backup copy uploaded to default storage`);
        } catch (backupError) {
          console.error(`[Storage] Failed to create backup copy:`, backupError);
        }
      }

      // Update document
      await storage.updateDocument(document.id, {
        status: "completed",
        signedPdfKey,
        signedPdfSha256: sha256,
      });

      // Log completion
      await logAuditEvent(document.id, "completed", req, { sha256 });

      console.log(`Document completed: ${document.id}`);
      console.log(`Signed PDF SHA-256: ${sha256}`);

      // Send final "Completed" webhook
      if (document.callbackUrl) {
        const signedPdfUrl = await objectStorage.getSignedDownloadUrl(
          signedPdfKey,
          86400 // 24 hours
        );

        // BoldSign-compatible webhook payload
        const webhookPayload = BOLDSIGN_COMPAT ? {
          event: "Completed",
          documentId: document.id,
          status: "completed",
          signed_pdf_url: signedPdfUrl,
          signed_pdf_sha256: sha256,
          template_id: document.templateId,
          data: document.dataJson,
        } : {
          event: "document.completed",
          document_id: document.id,
          status: "completed",
          signed_pdf_key: signedPdfKey,
          signed_pdf_url: signedPdfUrl,
          signed_pdf_sha256: sha256,
        };

        await sendWebhook(document.callbackUrl, webhookPayload);
        await logAuditEvent(document.id, "webhook_sent", req, { 
          callback_url: document.callbackUrl,
          compat_mode: BOLDSIGN_COMPAT ? "boldsign" : "default"
        });
      }

      // Send completion email with signed PDF attachment to all signers
      const documentTitle = docData?.title || docData?.tenant_name || "Document";
      
      // Use the already-fetched ownerVerified status for completion emails
      const senderVerified = ownerVerified;
      
      try {
        // Get all signers from document_signers table
        const documentSigners = await storage.getDocumentSigners(document.id);
        
        if (documentSigners.length > 0) {
          // Send to all signers from document_signers table
          for (const signer of documentSigners) {
            try {
              await sendCompletionEmailWithAttachment(
                document.id,
                signer.email,
                signer.name,
                documentTitle,
                signedPdfBuffer,
                senderVerified
              );
              await logAuditEvent(document.id, "completion_email_sent", req, { 
                recipientEmail: signer.email,
                hasAttachment: true 
              });
              console.log(`[EMAIL] Sent completion email with attachment to ${signer.email}`);
            } catch (signerEmailError) {
              console.error(`Failed to send completion email to ${signer.email}:`, signerEmailError);
            }
          }
        } else if (docData?.tenantEmail && typeof docData.tenantEmail === 'string' && docData.tenantEmail.includes('@')) {
          // Fallback for template-based documents without document_signers records
          await sendCompletionEmailWithAttachment(
            document.id,
            docData.tenantEmail,
            docData.tenant_name || "Tenant",
            documentTitle,
            signedPdfBuffer,
            senderVerified
          );
          await logAuditEvent(document.id, "completion_email_sent", req, { 
            recipientEmail: docData.tenantEmail,
            hasAttachment: true 
          });
          console.log(`[EMAIL] Sent completion email with attachment to ${docData.tenantEmail}`);
        } else {
          console.log(`[EMAIL] No signers found and no valid tenant email for document ${document.id}`);
        }
      } catch (completionEmailError) {
        console.error("Failed to send completion emails:", completionEmailError);
      }

      // Send completion notification to document owner (if exists)
      if (document.userId) {
        const ownerEmail = docData?.ownerEmail || docData?.landlordEmail;
        if (ownerEmail) {
          try {
            await sendCompletionNoticeEmail(document, ownerEmail, docData?.ownerName || docData?.landlordName, true);
            await logAuditEvent(document.id, "completion_email_sent", req, { recipientEmail: ownerEmail });
          } catch (emailError) {
            console.error("Failed to send completion email:", emailError);
          }
        }
      }

      res.json({
        success: true,
        document_id: document.id,
        status: "completed",
        sha256,
      });
    } catch (error) {
      console.error("Error completing document:", error);
      res.status(500).json({ error: "Failed to complete document" });
    }
  });

  // Proxy endpoint for unsigned PDF (avoids CORS issues with presigned URLs)
  app.get("/api/documents/:id/unsigned.pdf", validateToken, async (req: Request, res: Response) => {
    try {
      const document = (req as any).document;

      if (!document.unsignedPdfKey) {
        return res.status(404).json({ error: "Unsigned PDF not available" });
      }

      const privateDir = objectStorage.getPrivateObjectDir();
      const unsignedPath = joinStoragePath(privateDir, document.unsignedPdfKey);
      const pdfBuffer = await objectStorage.downloadBuffer(unsignedPath);

      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Cache-Control", "private, max-age=3600");
      res.send(pdfBuffer);
    } catch (error) {
      console.error("Error proxying unsigned PDF:", error);
      res.status(500).json({ error: "Failed to load PDF" });
    }
  });

  // Proxy endpoint for signature images (for rendering on PDF preview)
  app.get("/api/documents/:id/signature-image/:spotKey", validateToken, async (req: Request, res: Response) => {
    try {
      const document = (req as any).document;
      const { spotKey } = req.params;

      // Get the signature asset for this spot
      const assets = await storage.getSignatureAssets(document.id);
      const asset = assets.find(a => a.spotKey === spotKey);

      if (!asset || !asset.imageKey) {
        return res.status(404).json({ error: "Signature not found" });
      }

      const privateDir = objectStorage.getPrivateObjectDir();
      const imagePath = joinStoragePath(privateDir, asset.imageKey);
      const imageBuffer = await objectStorage.downloadBuffer(imagePath);

      res.setHeader("Content-Type", "image/png");
      res.setHeader("Cache-Control", "private, max-age=3600");
      res.send(imageBuffer);
    } catch (error) {
      console.error("Error serving signature image:", error);
      res.status(500).json({ error: "Failed to load signature image" });
    }
  });

  // Download signed PDF
  app.get("/api/documents/:id/signed.pdf", validateToken, async (req: Request, res: Response) => {
    try {
      const document = (req as any).document;

      if (document.status !== "completed" || !document.signedPdfKey) {
        return res.status(404).json({ error: "Signed PDF not available" });
      }

      const privateDir = objectStorage.getPrivateObjectDir();
      const signedPath = joinStoragePath(privateDir, document.signedPdfKey);
      const signedPdfBuffer = await objectStorage.downloadBuffer(signedPath);

      res.setHeader("Content-Type", "application/pdf");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="signed-${document.id}.pdf"`
      );
      res.send(signedPdfBuffer);
    } catch (error) {
      console.error("Error downloading signed PDF:", error);
      res.status(500).json({ error: "Failed to download signed PDF" });
    }
  });


  // Webhook test endpoint (for development)
  app.post("/api/webhook-test", (req: Request, res: Response) => {
    console.log("=== WEBHOOK RECEIVED ===");
    console.log("Headers:", req.headers);
    console.log("Body:", req.body);
    console.log("========================");
    res.json({ received: true });
  });

  // ============ BOLDSIGN COMPATIBILITY ENDPOINTS ============

  // BoldSign-compatible: Get embedded signing link
  // GET /api/document/getEmbeddedSignLink?documentId=...&signerEmail=...
  app.get("/api/document/getEmbeddedSignLink", validateInternalApiKey, async (req: Request, res: Response) => {
    try {
      const documentId = req.query.documentId as string;
      const signerEmail = req.query.signerEmail as string;

      if (!documentId) {
        return res.status(400).json({ error: "documentId required" });
      }

      if (documentId.includes("/") || documentId.includes("\\") || documentId.includes("..")) {
        return res.status(400).json({ error: "Invalid documentId" });
      }

      const document = await storage.getDocument(documentId);
      if (!document) {
        return res.status(404).json({ error: "Document not found" });
      }

      const baseUrl = process.env.BASE_URL || `https://${req.headers.host}`;
      let signLink: string;

      // Check for multi-signer: look up signer by email if provided
      if (signerEmail) {
        const signer = await storage.getDocumentSignerByEmail(documentId, signerEmail);
        if (signer) {
          signLink = `${baseUrl}/d/${document.id}?token=${signer.token}`;
          console.log(`[BoldSign Compat] Multi-signer link for ${signerEmail}`);
        } else {
          // Fallback to document-level token if no signer record found
          signLink = `${baseUrl}/d/${document.id}?token=${document.signingToken}`;
          console.log(`[BoldSign Compat] No signer found for ${signerEmail}, using document token`);
        }
      } else {
        // Single-signer: use document-level token
        signLink = `${baseUrl}/d/${document.id}?token=${document.signingToken}`;
      }

      // Log audit event
      await logAuditEvent(document.id, "embedded_link_requested", req, { 
        signerEmail: signerEmail || "not_provided" 
      });

      console.log(`[BoldSign Compat] Embedded link requested for ${documentId}${signerEmail ? ` (signer: ${signerEmail})` : ""}`);

      res.json({ signLink });
    } catch (error) {
      console.error("Error getting embedded sign link:", error);
      res.status(500).json({ error: "Failed to get embedded sign link" });
    }
  });

  // BoldSign-compatible: Download signed document
  // GET /api/document/download?documentId=...
  app.get("/api/document/download", validateInternalApiKey, async (req: Request, res: Response) => {
    try {
      const documentId = req.query.documentId as string;

      if (!documentId) {
        return res.status(400).json({ error: "documentId required" });
      }

      if (documentId.includes("/") || documentId.includes("\\") || documentId.includes("..")) {
        return res.status(400).json({ error: "Invalid documentId" });
      }

      const document = await storage.getDocument(documentId);
      if (!document) {
        return res.status(404).json({ error: "Document not found" });
      }

      if (document.status !== "completed" || !document.signedPdfKey) {
        return res.status(409).json({ error: "Document not yet completed" });
      }

      // Log audit event
      await logAuditEvent(document.id, "internal_download", req);

      const privateDir = objectStorage.getPrivateObjectDir();
      const signedPath = joinStoragePath(privateDir, document.signedPdfKey);
      const signedPdfBuffer = await objectStorage.downloadBuffer(signedPath);

      console.log(`[BoldSign Compat] Internal download for ${documentId}`);

      res.setHeader("Content-Type", "application/pdf");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="signed-${document.id}.pdf"`
      );
      res.send(signedPdfBuffer);
    } catch (error) {
      console.error("Error downloading document:", error);
      res.status(500).json({ error: "Failed to download document" });
    }
  });

  // ============ ADMIN ENDPOINTS ============

  // Get all documents for authenticated user (admin dashboard) - includes team documents
  app.get("/api/admin/documents", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      // Get accessible user IDs (self + team members)
      const accessibleUserIds = await getAccessibleUserIds(userId);
      
      // Fetch documents from all accessible users
      let allDocuments: any[] = [];
      for (const uid of accessibleUserIds) {
        const docs = await storage.getDocumentsByUser(uid);
        allDocuments = allDocuments.concat(docs);
      }
      
      // Sort by createdAt descending
      allDocuments.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
      
      res.json(allDocuments);
    } catch (error) {
      console.error("Error fetching admin documents:", error);
      res.status(500).json({ error: "Failed to fetch documents" });
    }
  });

  // Get single document detail for admin
  app.get("/api/admin/documents/:id", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      const documentId = req.params.id;

      const document = await storage.getDocument(documentId);
      if (!document) {
        return res.status(404).json({ error: "Document not found" });
      }

      // Verify ownership or team membership
      const hasAccess = await canAccessUserDocuments(userId, document.userId);
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied" });
      }

      // Get signature assets and audit events
      const signatureAssets = await storage.getSignatureAssets(documentId);
      const auditEvents = await storage.getAuditEvents(documentId);

      res.json({
        ...document,
        signatureAssets,
        auditEvents,
      });
    } catch (error) {
      console.error("Error fetching document detail:", error);
      res.status(500).json({ error: "Failed to fetch document" });
    }
  });

  // Archive a document
  app.post("/api/admin/documents/:id/archive", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      const documentId = req.params.id;

      const document = await storage.getDocument(documentId);
      if (!document) {
        return res.status(404).json({ error: "Document not found" });
      }

      // Verify ownership or team membership
      const hasAccess = await canAccessUserDocuments(userId, document.userId);
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (document.status === "completed") {
        return res.status(400).json({ error: "Cannot archive completed documents" });
      }

      const updated = await storage.updateDocument(documentId, {
        archivedAt: new Date(),
      });

      res.json({ success: true, document: updated });
    } catch (error) {
      console.error("Error archiving document:", error);
      res.status(500).json({ error: "Failed to archive document" });
    }
  });

  // Unarchive a document
  app.post("/api/admin/documents/:id/unarchive", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      const documentId = req.params.id;

      const document = await storage.getDocument(documentId);
      if (!document) {
        return res.status(404).json({ error: "Document not found" });
      }

      // Verify ownership or team membership
      const hasAccess = await canAccessUserDocuments(userId, document.userId);
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied" });
      }

      const updated = await storage.updateDocument(documentId, {
        archivedAt: null,
      });

      res.json({ success: true, document: updated });
    } catch (error) {
      console.error("Error unarchiving document:", error);
      res.status(500).json({ error: "Failed to unarchive document" });
    }
  });

  // Admin endpoint to view/download signed PDF
  app.get("/api/admin/documents/:id/signed.pdf", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      const documentId = req.params.id;
      const download = req.query.download === "true";

      const document = await storage.getDocument(documentId);
      if (!document) {
        return res.status(404).json({ error: "Document not found" });
      }

      // Verify ownership or team membership
      const hasAccess = await canAccessUserDocuments(userId, document.userId);
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (document.status !== "completed" || !document.signedPdfKey) {
        return res.status(400).json({ error: "Document not completed or signed PDF not available" });
      }

      const pdfBuffer = await objectStorage.downloadBuffer(document.signedPdfKey);
      
      res.setHeader("Content-Type", "application/pdf");
      if (download) {
        res.setHeader("Content-Disposition", `attachment; filename="signed-${documentId}.pdf"`);
      } else {
        res.setHeader("Content-Disposition", `inline; filename="signed-${documentId}.pdf"`);
      }
      res.send(pdfBuffer);
    } catch (error) {
      console.error("Error fetching signed PDF:", error);
      res.status(500).json({ error: "Failed to fetch signed PDF" });
    }
  });

  // Create document as authenticated user
  app.post("/api/admin/documents", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      // Admin accounts cannot create documents - they are for platform management only
      const user = await authStorage.getUser(userId);
      if (user?.isAdmin) {
        return res.status(403).json({ error: "Admin accounts cannot create documents. Admin accounts are for platform management only." });
      }

      // Check document usage limits for free accounts
      const usage = await authStorage.checkDocumentUsage(userId);
      if (!usage.canCreate) {
        return res.status(403).json({
          error: "Document limit reached",
          message: `You have reached your monthly limit of ${usage.limit} documents. Upgrade to Pro for unlimited documents.`,
          usage: { used: usage.used, limit: usage.limit, accountType: usage.accountType },
        });
      }

      const parseResult = createDocumentRequestSchema.safeParse(req.body);
      if (!parseResult.success) {
        return res.status(400).json({
          error: "Invalid request",
          details: parseResult.error.errors,
        });
      }

      const { template_id, data, callback_url } = parseResult.data;

      // Generate signing token
      const signingToken = nanoid(32);

      // Render document from template (supports both HTML and PDF templates)
      console.log(`Rendering document from template: ${template_id} (user: ${userId})`);
      const pdfBuffer = await renderDocumentFromTemplate(template_id, data);

      // Calculate SHA-256 hash of the original rendered PDF before any modifications
      const originalHash = createHash("sha256").update(pdfBuffer).digest("hex");

      // Get storage context based on user's data region setting
      const storageContext = await resolveDocumentStorageContext(userId);

      // Upload unsigned PDF to region-specific storage backend
      const unsignedPdfKey = `documents/${nanoid()}/unsigned.pdf`;
      await storageContext.backend.uploadBuffer(pdfBuffer, unsignedPdfKey, "application/pdf");

      // Create document record with userId and storage bucket info
      const document = await storage.createDocument({
        userId,
        templateId: template_id,
        status: "created",
        dataJson: data,
        callbackUrl: callback_url || null,
        signingToken,
        unsignedPdfKey,
        signedPdfKey: null,
        signedPdfSha256: null,
        originalHash, // SHA-256 hash of original PDF before modifications
        storageBucket: storageContext.storageBucket,
        storageRegion: storageContext.storageRegion,
      });

      // Log audit event
      await logAuditEvent(document.id, "document_created", req, { template_id, userId });

      // Increment document count for free users
      await authStorage.incrementDocumentCount(userId);

      const baseUrl = process.env.BASE_URL || `https://${req.headers.host}`;
      const signingUrl = `${baseUrl}/d/${document.id}?token=${signingToken}`;

      console.log(`Admin document created: ${document.id} by user ${userId}`);

      res.status(201).json({
        document_id: document.id,
        signing_url: signingUrl,
        status: document.status,
      });
    } catch (error) {
      console.error("Error creating admin document:", error);
      res.status(500).json({ error: "Failed to create document" });
    }
  });

  // Create document from PDF template with creator-filled fields
  app.post("/api/admin/documents/from-template", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      // Admin accounts cannot create documents - they are for platform management only
      const user = await authStorage.getUser(userId);
      if (user?.isAdmin) {
        return res.status(403).json({ error: "Admin accounts cannot create documents. Admin accounts are for platform management only." });
      }

      const { templateId, signers, creatorFieldValues, sendEmail } = req.body;

      if (!templateId) {
        return res.status(400).json({ error: "Template ID is required" });
      }

      if (!signers || !Array.isArray(signers) || signers.length === 0) {
        return res.status(400).json({ error: "At least one signer is required" });
      }

      // Check signer limit for Free users
      const tierLimits = getTierLimits(user?.accountType);
      if (tierLimits.signersPerDocument > 0 && signers.length > tierLimits.signersPerDocument) {
        return res.status(403).json({
          error: "Signer limit exceeded",
          message: `Free accounts can only have ${tierLimits.signersPerDocument} signers per document. Upgrade to Pro for unlimited signers.`,
          limit: tierLimits.signersPerDocument,
          requested: signers.length,
        });
      }

      // Fetch template
      const template = await storage.getTemplate(templateId);
      if (!template) {
        return res.status(404).json({ error: "Template not found" });
      }

      if (template.templateType !== "pdf" || !template.pdfStorageKey) {
        return res.status(400).json({ error: "Template must be a PDF template" });
      }

      // Fetch template fields
      const templateFields = await storage.getTemplateFields(templateId);

      // Download the template PDF
      const pdfBuffer = await objectStorage.downloadBuffer(template.pdfStorageKey);

      // Calculate SHA-256 hash of the original template PDF before any modifications
      const originalHash = createHash("sha256").update(pdfBuffer).digest("hex");

      // Stamp creator-filled fields onto the PDF
      let modifiedPdfBuffer = pdfBuffer;
      
      const creatorFillFields = templateFields.filter(f => f.creatorFills);
      if (creatorFillFields.length > 0 && creatorFieldValues) {
        const { PDFDocument, rgb, StandardFonts } = await import("pdf-lib");
        const pdfDoc = await PDFDocument.load(pdfBuffer);
        const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
        const pages = pdfDoc.getPages();

        for (const field of creatorFillFields) {
          const value = creatorFieldValues[field.apiTag];
          if (!value) continue;

          const pageIndex = field.page - 1;
          if (pageIndex < 0 || pageIndex >= pages.length) continue;

          const page = pages[pageIndex];
          const pageHeight = page.getHeight();
          
          // Convert from top-origin to bottom-origin
          const x = Number(field.x);
          const y = pageHeight - Number(field.y) - Number(field.height);
          const fontSize = field.fontSize || 12;

          if (field.fieldType === "checkbox") {
            if (value === "true") {
              // Draw an X checkmark (guaranteed to render in Helvetica)
              page.drawText("X", {
                x: x + 2,
                y: y + 2,
                size: Math.min(Number(field.width), Number(field.height)) * 0.7,
                font,
                color: rgb(0, 0, 0),
              });
            }
          } else if (field.fieldType === "date") {
            // Format the date nicely
            const dateValue = new Date(value);
            const formattedDate = !isNaN(dateValue.getTime()) 
              ? dateValue.toLocaleDateString("en-US") 
              : value;
            page.drawText(formattedDate, {
              x,
              y: y + 4,
              size: fontSize,
              font,
              color: rgb(0, 0, 0),
            });
          } else {
            // Text field
            page.drawText(value, {
              x,
              y: y + 4,
              size: fontSize,
              font,
              color: rgb(0, 0, 0),
            });
          }
        }

        modifiedPdfBuffer = Buffer.from(await pdfDoc.save());
      }

      // Get storage context based on user's data region setting
      const storageContext = await resolveDocumentStorageContext(userId);

      // Upload the modified PDF to region-specific storage backend
      const unsignedPdfKey = `documents/${nanoid()}/unsigned.pdf`;
      await storageContext.backend.uploadBuffer(modifiedPdfBuffer, unsignedPdfKey, "application/pdf");

      // Generate document-level signing token
      const signingToken = nanoid(32);

      // Convert template fields to document field format (matching one-off document structure)
      const documentFields = templateFields
        .filter(f => !f.creatorFills) // Exclude creator-filled fields (they're stamped on PDF)
        .map((field, idx) => ({
          id: `field_${Date.now()}_${idx}`,
          fieldType: field.fieldType,
          signerId: field.signerRole, // Use signerRole as signerId for template-based documents
          page: field.page,
          x: Number(field.x),
          y: Number(field.y),
          width: Number(field.width),
          height: Number(field.height),
          required: field.required ?? true,
          label: field.label || field.apiTag,
          placeholder: field.placeholder || "",
          inputMode: field.inputMode || "any",
          isDocumentDate: field.isDocumentDate || false,
        }));

      // Create document record with storage bucket info
      const document = await storage.createDocument({
        userId,
        templateId,
        status: "created",
        dataJson: {
          signers,
          fields: documentFields,
          creatorFieldValues,
          fromTemplate: true,
        },
        callbackUrl: null,
        signingToken,
        unsignedPdfKey,
        signedPdfKey: null,
        signedPdfSha256: null,
        originalHash, // SHA-256 hash of original template PDF before modifications
        storageBucket: storageContext.storageBucket,
        storageRegion: storageContext.storageRegion,
      });

      console.log(`[From Template] Document created: ${document.id} from template ${templateId}`);

      await logAuditEvent(document.id, "document_created", req, { 
        userId, 
        templateId,
        signerCount: signers.length,
      });

      const baseUrl = process.env.BASE_URL || `https://${req.headers.host}`;
      const signerLinks: Array<{ email: string; name: string; role: string; signLink: string }> = [];

      // Sort signers by provided orderIndex for sequential signing
      const sortedSigners = [...signers].sort((a, b) => {
        const aOrder = typeof a.orderIndex === "number" ? a.orderIndex : signers.indexOf(a);
        const bOrder = typeof b.orderIndex === "number" ? b.orderIndex : signers.indexOf(b);
        return aOrder - bOrder;
      });

      // Create signer records and signature spots from template fields
      for (let i = 0; i < sortedSigners.length; i++) {
        const signer = sortedSigners[i];
        const signerToken = nanoid(32);
        const orderIndex = typeof signer.orderIndex === "number" ? signer.orderIndex : i;
        
        await storage.createDocumentSigner({
          documentId: document.id,
          email: signer.email,
          name: signer.name,
          role: signer.role,
          token: signerToken,
          status: "pending",
          orderIndex,
        });

        const signLink = `${baseUrl}/d/${document.id}?token=${signerToken}`;
        signerLinks.push({
          email: signer.email,
          name: signer.name,
          role: signer.role,
          signLink,
        });

        await logAuditEvent(document.id, "signer_added", req, { 
          signerEmail: signer.email, 
          signerRole: signer.role,
        });
      }

      // Send emails if requested
      let emailsSent = false;
      if (sendEmail) {
        // Send to first signer only (sequential signing - others get notified when previous completes)
        const firstSignerLink = signerLinks[0];
        if (firstSignerLink) {
          try {
            await sendSigningEmail(
              firstSignerLink.email,
              firstSignerLink.name,
              firstSignerLink.signLink,
              `Document: ${template.name}`
            );
            emailsSent = true;
            await logAuditEvent(document.id, "email_sent", req, {
              signerEmail: firstSignerLink.email,
            });
          } catch (emailError) {
            console.error("Error sending email:", emailError);
          }
        }
      }

      res.status(201).json({
        document_id: document.id,
        documentId: document.id,
        signers: signerLinks,
        status: "created",
        emailsSent,
      });
    } catch (error) {
      console.error("Error creating document from template:", error);
      res.status(500).json({ error: "Failed to create document" });
    }
  });

  // Create one-off document (no template, direct PDF upload with signers and fields)
  app.post("/api/admin/documents/one-off", isAuthenticated, upload.single("pdf"), async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      // Admin accounts cannot create documents - they are for platform management only
      const userRecord = await authStorage.getUser(userId);
      if (userRecord?.isAdmin) {
        return res.status(403).json({ error: "Admin accounts cannot create documents. Admin accounts are for platform management only." });
      }

      // Check document usage limits for free accounts
      const usage = await authStorage.checkDocumentUsage(userId);
      if (!usage.canCreate) {
        return res.status(403).json({
          error: "Document limit reached",
          message: `You have reached your monthly limit of ${usage.limit} documents. Upgrade to Pro for unlimited documents.`,
          usage: { used: usage.used, limit: usage.limit, accountType: usage.accountType },
        });
      }

      const file = req.file;
      if (!file) {
        return res.status(400).json({ error: "PDF file is required" });
      }

      // Parse signers and fields from form data
      let signers: Array<{ name: string; email: string; id: string }>;
      let fields: Array<{
        id: string;
        fieldType: string;
        signerId: string;
        page: number;
        x: number;
        y: number;
        width: number;
        height: number;
        required: boolean;
        label?: string;
        placeholder?: string;
        inputMode?: string;
        creatorFills?: boolean;
        creatorValue?: string;
        isDocumentDate?: boolean;
      }>;
      let documentTitle: string;
      let sendEmails: boolean;

      try {
        signers = JSON.parse(req.body.signers || "[]");
        fields = JSON.parse(req.body.fields || "[]");
        documentTitle = req.body.title || "Document";
        sendEmails = req.body.sendEmails === "true";
      } catch (parseError) {
        return res.status(400).json({ error: "Invalid JSON in signers or fields" });
      }

      // Validate signers
      if (!Array.isArray(signers) || signers.length === 0) {
        return res.status(400).json({ error: "At least one signer is required" });
      }

      // Check signer limit for Free users
      const tierLimits = getTierLimits(userRecord?.accountType);
      if (tierLimits.signersPerDocument > 0 && signers.length > tierLimits.signersPerDocument) {
        return res.status(403).json({
          error: "Signer limit exceeded",
          message: `Free accounts can only have ${tierLimits.signersPerDocument} signers per document. Upgrade to Pro for unlimited signers.`,
          limit: tierLimits.signersPerDocument,
          requested: signers.length,
        });
      }

      for (const signer of signers) {
        if (!signer.name || !signer.email || !signer.id) {
          return res.status(400).json({ error: "Each signer must have name, email, and id" });
        }
      }

      // Validate fields
      if (!Array.isArray(fields)) {
        return res.status(400).json({ error: "Fields must be an array" });
      }

      for (const field of fields) {
        if (!field.signerId || !field.fieldType || typeof field.page !== "number") {
          return res.status(400).json({ error: "Each field must have signerId, fieldType, and page" });
        }
        // Verify signer exists
        if (!signers.find(s => s.id === field.signerId)) {
          return res.status(400).json({ error: `Field references unknown signer: ${field.signerId}` });
        }
        // Reject creatorFills on signature/initial fields - those must always be filled by signers
        if (field.creatorFills && (field.fieldType === "signature" || field.fieldType === "initial")) {
          return res.status(400).json({ 
            error: "Signature and initial fields cannot be set as 'Creator Fills'. Only text, date, and checkbox fields can be pre-filled by the creator." 
          });
        }
      }

      // Calculate SHA-256 hash of the original PDF before any modifications
      // This allows third-party verification of the original blank document
      const originalHash = createHash("sha256").update(file.buffer).digest("hex");
      console.log(`[One-Off] Original document hash: ${originalHash}`);

      // Stamp creator-filled fields onto the PDF before uploading
      let pdfBuffer = file.buffer;
      const creatorFillFields = fields.filter(f => f.creatorFills && f.creatorValue);
      
      if (creatorFillFields.length > 0) {
        console.log(`[One-Off] Stamping ${creatorFillFields.length} creator-filled fields onto PDF`);
        const { PDFDocument, rgb, StandardFonts } = await import("pdf-lib");
        const pdfDoc = await PDFDocument.load(pdfBuffer);
        const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
        const pages = pdfDoc.getPages();

        for (const field of creatorFillFields) {
          const value = field.creatorValue;
          if (!value) continue;

          const page = pages[field.page - 1];
          if (!page) continue;

          const pageHeight = page.getHeight();
          // Convert top-origin to bottom-origin for pdf-lib
          const pdfY = pageHeight - field.y - field.height;

          if (field.fieldType === "text" || field.fieldType === "date") {
            const fontSize = Math.min(field.height * 0.7, 12);
            page.drawText(value, {
              x: field.x + 2,
              y: pdfY + field.height * 0.3,
              size: fontSize,
              font,
              color: rgb(0, 0, 0),
            });
          } else if (field.fieldType === "checkbox") {
            if (value === "true" || value === "checked" || value === "1") {
              const fontSize = field.height * 0.8;
              page.drawText("X", {
                x: field.x + field.width * 0.25,
                y: pdfY + field.height * 0.15,
                size: fontSize,
                font,
                color: rgb(0, 0, 0),
              });
            }
          }
        }

        pdfBuffer = Buffer.from(await pdfDoc.save());
        console.log(`[One-Off] Creator-filled fields stamped successfully`);
      }

      // Get storage context based on user's data region setting
      const storageContext = await resolveDocumentStorageContext(userId);

      // Upload PDF to region-specific storage backend
      const unsignedPdfKey = `documents/${nanoid()}/unsigned.pdf`;
      await storageContext.backend.uploadBuffer(pdfBuffer, unsignedPdfKey, "application/pdf");
      console.log(`[One-Off] Uploaded PDF: ${unsignedPdfKey} to ${storageContext.storageRegion} region`);

      // Generate document-level signing token (for backward compatibility)
      const signingToken = nanoid(32);

      // Create document record with null templateId and storage bucket info
      const document = await storage.createDocument({
        userId,
        templateId: null,
        status: "created",
        dataJson: {
          title: documentTitle,
          signers,
          fields,
          oneOffDocument: true,
        },
        callbackUrl: null,
        signingToken,
        unsignedPdfKey,
        signedPdfKey: null,
        signedPdfSha256: null,
        originalHash, // SHA-256 hash of original blank PDF before modifications
        storageBucket: storageContext.storageBucket,
        storageRegion: storageContext.storageRegion,
      });

      console.log(`[One-Off] Document created: ${document.id}`);

      // Persist creator-filled text/date/checkbox values to storage so signing UI receives them
      for (const field of creatorFillFields) {
        if (field.creatorValue) {
          await storage.saveTextFieldValue({
            documentId: document.id,
            spotKey: field.id,
            value: field.creatorValue,
            fieldType: field.fieldType,
            signerRole: "creator",
            signerEmail: "creator@system",
          });
          console.log(`[One-Off] Persisted creator-filled value for field ${field.id}`);
        }
      }

      // Log audit event
      await logAuditEvent(document.id, "document_created", req, { 
        userId, 
        oneOffDocument: true,
        signerCount: signers.length,
        fieldCount: fields.length,
        creatorFilledCount: creatorFillFields.length,
      });

      // Increment document count for free users
      await authStorage.incrementDocumentCount(userId);

      const baseUrl = process.env.BASE_URL || `https://${req.headers.host}`;
      const signerLinks: Array<{ id: string; email: string; name: string; signLink: string; emailSent: boolean }> = [];

      // Create signer records with order and only send email to first signer
      for (let orderIndex = 0; orderIndex < signers.length; orderIndex++) {
        const signer = signers[orderIndex];
        const signerToken = nanoid(32);
        await storage.createDocumentSigner({
          documentId: document.id,
          email: signer.email,
          name: signer.name,
          role: signer.id, // Use signer.id as "role" for field matching
          token: signerToken,
          status: "pending",
          orderIndex, // Track signing order
        });

        const signLink = `${baseUrl}/d/${document.id}?token=${signerToken}`;
        let emailSent = false;

        // Only send email to the first signer (orderIndex 0) for sequential signing
        if (sendEmails && orderIndex === 0) {
          try {
            // Check if document owner is identity verified and get sender name
            const owner = await authStorage.getUser(userId);
            const senderVerified = !!owner?.identityVerifiedAt;
            const senderName = owner ? `${owner.firstName || ''} ${owner.lastName || ''}`.trim() || owner.email : undefined;
            
            const { sendSignatureRequestEmailWithUrl } = await import("./services/emailService");
            await sendSignatureRequestEmailWithUrl(
              document.id,
              signer.email,
              signer.name,
              signLink,
              documentTitle,
              senderVerified,
              senderName
            );
            emailSent = true;
            console.log(`[One-Off] Email sent to first signer: ${signer.email}`);
          } catch (emailError) {
            console.error(`[One-Off] Failed to send email to ${signer.email}:`, emailError);
          }
        }

        signerLinks.push({
          id: signer.id,
          email: signer.email,
          name: signer.name,
          signLink,
          emailSent,
        });

        await logAuditEvent(document.id, "signer_added", req, { 
          signerEmail: signer.email, 
          signerRole: signer.id,
          orderIndex,
        });
      }

      // Update status to 'sent' if emails were dispatched
      if (sendEmails && signerLinks.some(s => s.emailSent)) {
        await storage.updateDocument(document.id, { status: "sent" });
      }

      console.log(`[One-Off] Document ${document.id} created with ${signers.length} signers`);

      res.status(201).json({
        success: true,
        document_id: document.id,
        documentId: document.id,
        title: documentTitle,
        signers: signerLinks,
        status: sendEmails ? "sent" : "created",
      });
    } catch (error) {
      console.error("[One-Off] Error creating document:", error);
      res.status(500).json({ error: "Failed to create one-off document" });
    }
  });

  // ============ STORAGE SETTINGS ENDPOINTS ============

  // Get current storage settings for user
  app.get("/api/storage/settings", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      const user = await authStorage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const credentials = await authStorage.getAllStorageCredentials(userId);
      const connectedProviders = credentials.map(c => ({
        provider: c.provider,
        email: c.providerEmail,
        connectedAt: c.createdAt,
      }));

      // Check if user has custom S3 credentials
      const customS3Creds = await authStorage.getUserS3Credentials(userId);
      const hasCustomS3 = !!customS3Creds;

      const { getAvailableProviders, isProviderConfigured } = await import("./services/externalStorage");
      const { isS3StorageAvailable: s3Available } = await import("./services/storageBackend");

      const isPro = user.accountType === "pro" || user.accountType === "enterprise";

      const providers = getAvailableProviders().map(p => ({
        ...p,
        connected: p.provider === "fairsign" 
          ? true 
          : p.provider === "custom_s3"
            ? hasCustomS3
            : connectedProviders.some(c => c.provider === p.provider),
        configured: isProviderConfigured(p.provider),
        connectedEmail: connectedProviders.find(c => c.provider === p.provider)?.email,
        // Pro-only providers are hidden for free users
        hidden: p.requiresPro && !isPro,
      }));

      res.json({
        currentProvider: user.storageProvider || "fairsign",
        encryptionEnabled: !!(user.encryptionKeyId),
        encryptionSalt: user.encryptionKeySalt,
        providers,
        s3Available: s3Available(),
        isPro,
      });
    } catch (error) {
      console.error("Error fetching storage settings:", error);
      res.status(500).json({ error: "Failed to fetch storage settings" });
    }
  });

  // Update storage provider preference
  app.post("/api/storage/settings", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      const { updateStoragePreferenceSchema } = await import("@shared/models/auth");
      const parsed = updateStoragePreferenceSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request", details: parsed.error.errors });
      }

      const { storageProvider } = parsed.data;

      // Get user to check account type
      const user = await authStorage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Pro-only providers check
      const isPro = user.accountType === "pro" || user.accountType === "enterprise";
      if (["custom_s3", "google_drive", "dropbox", "box"].includes(storageProvider) && !isPro) {
        return res.status(403).json({ error: "This storage provider is only available for Pro accounts" });
      }

      // Verify provider is connected (except for fairsign which is always available)
      if (storageProvider !== "fairsign") {
        if (storageProvider === "custom_s3") {
          const s3Creds = await authStorage.getUserS3Credentials(userId);
          if (!s3Creds) {
            return res.status(400).json({ error: "Please configure your S3 credentials first" });
          }
        } else {
          const creds = await authStorage.getStorageCredentials(userId, storageProvider);
          if (!creds) {
            return res.status(400).json({ error: `Please connect your ${storageProvider} account first` });
          }
        }
      }

      const updatedUser = await authStorage.updateStorageProvider(userId, storageProvider);
      res.json({ success: true, storageProvider: updatedUser?.storageProvider });
    } catch (error) {
      console.error("Error updating storage settings:", error);
      res.status(500).json({ error: "Failed to update storage settings" });
    }
  });

  // Setup encryption for FairSign storage
  app.post("/api/storage/encryption/setup", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      const { salt } = req.body;
      if (!salt) {
        return res.status(400).json({ error: "Salt is required" });
      }

      const keyId = `enc_${userId}_${Date.now()}`;
      const user = await authStorage.updateEncryptionKey(userId, keyId, salt);
      
      res.json({ 
        success: true, 
        encryptionKeyId: keyId,
        message: "Encryption key setup complete. Your documents will now be encrypted."
      });
    } catch (error) {
      console.error("Error setting up encryption:", error);
      res.status(500).json({ error: "Failed to setup encryption" });
    }
  });

  // ============ DATA RESIDENCY ============
  
  // Get data residency settings
  app.get("/api/user/data-region", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      const user = await authStorage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const { isRegionalStorageAvailable } = await import("./services/storageBackend");
      
      res.json({
        dataRegion: user.dataRegion || "EU",
        isEnterprise: user.accountType === "enterprise",
        canChange: user.accountType === "enterprise",
        available: isRegionalStorageAvailable(),
        regions: [
          { value: "EU", label: "Europe (Ireland/Germany) - Default" },
          { value: "US", label: "United States (Virginia)" },
        ],
      });
    } catch (error) {
      console.error("Error fetching data region:", error);
      res.status(500).json({ error: "Failed to fetch data region settings" });
    }
  });

  // Update data region (Enterprise only) - uses feature access middleware
  app.patch("/api/user/data-region", isAuthenticated, checkFeatureAccess("data_residency"), async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      const user = await authStorage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const { dataRegion } = req.body;
      if (!dataRegion || !["EU", "US"].includes(dataRegion)) {
        return res.status(400).json({ error: "Invalid data region. Must be 'EU' or 'US'." });
      }

      // Check if regional storage is available
      const { isRegionalStorageAvailable } = await import("./services/storageBackend");
      if (!isRegionalStorageAvailable() && dataRegion === "US") {
        return res.status(400).json({ error: "US region is not currently available" });
      }

      const updatedUser = await authStorage.updateDataRegion(userId, dataRegion);
      
      res.json({
        success: true,
        dataRegion: updatedUser?.dataRegion,
        message: `Data residency updated to ${dataRegion}. New documents will be stored in the ${dataRegion === "EU" ? "European" : "United States"} region.`,
      });
    } catch (error) {
      console.error("Error updating data region:", error);
      res.status(500).json({ error: "Failed to update data region" });
    }
  });

  // ============ ALLOWED ORIGINS (Enterprise Embedded Signing API) ============
  
  // Get allowed origins for embedded signing
  app.get("/api/user/allowed-origins", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      const user = await authStorage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      const isEnterpriseUser = user.accountType === "enterprise";
      
      res.json({
        allowedOrigins: user.allowedOrigins || [],
        isEnterprise: isEnterpriseUser,
        canEdit: isEnterpriseUser,
      });
    } catch (error) {
      console.error("Error fetching allowed origins:", error);
      res.status(500).json({ error: "Failed to fetch allowed origins" });
    }
  });

  // Update allowed origins for embedded signing (Enterprise only)
  app.patch("/api/user/allowed-origins", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      const user = await authStorage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // STRICT Enterprise-only enforcement using shared tier helper
      if (!isEnterprise(user.accountType)) {
        return res.status(403).json({
          error: "Enterprise subscription required",
          message: "Configuring allowed origins for embedded signing is an Enterprise-only feature.",
        });
      }

      const { allowedOrigins } = req.body;
      if (!Array.isArray(allowedOrigins)) {
        return res.status(400).json({ error: "allowedOrigins must be an array of URLs" });
      }

      // Validate each origin is a valid URL with protocol
      const validOrigins: string[] = [];
      for (const origin of allowedOrigins) {
        if (typeof origin !== "string" || !origin.trim()) continue;
        try {
          const url = new URL(origin.trim());
          // Only allow http/https origins
          if (url.protocol !== "http:" && url.protocol !== "https:") {
            return res.status(400).json({ error: `Invalid origin protocol: ${origin}. Must be http or https.` });
          }
          // Store just the origin (protocol + host + port)
          validOrigins.push(url.origin);
        } catch {
          return res.status(400).json({ error: `Invalid URL format: ${origin}` });
        }
      }

      // Import db and users for update
      const { db } = await import("./db");
      const { users } = await import("@shared/models/auth");
      const { eq } = await import("drizzle-orm");

      await db.update(users).set({
        allowedOrigins: validOrigins,
        updatedAt: new Date(),
      }).where(eq(users.id, userId));

      res.json({
        success: true,
        allowedOrigins: validOrigins,
        message: `Updated allowed origins. ${validOrigins.length} origin(s) configured for embedded signing.`,
      });
    } catch (error) {
      console.error("Error updating allowed origins:", error);
      res.status(500).json({ error: "Failed to update allowed origins" });
    }
  });

  // ============ USER ACCOUNT DELETION ============
  
  // User self-deletion (soft delete with 30-day grace period)
  app.delete("/api/account", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      const user = await authStorage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      if (user.isAdmin) {
        return res.status(400).json({ error: "Admin accounts cannot be self-deleted" });
      }

      if (user.deletedAt) {
        return res.status(400).json({ error: "Account is already scheduled for deletion" });
      }

      // Calculate scheduled deletion date
      // For paid users with active subscription, deletion starts when subscription ends
      let scheduledDeletionDate = new Date();
      let gracePeriodStart = new Date();
      
      if (user.accountType === "pro" && 
          user.subscriptionCurrentPeriodEnd && 
          user.subscriptionCurrentPeriodEnd > new Date()) {
        // Account stays active until subscription ends, then 30-day grace period
        gracePeriodStart = new Date(user.subscriptionCurrentPeriodEnd);
        scheduledDeletionDate = new Date(user.subscriptionCurrentPeriodEnd);
      }
      scheduledDeletionDate.setDate(scheduledDeletionDate.getDate() + 30);

      // Import db and users for update
      const { db } = await import("./db");
      const { users } = await import("@shared/models/auth");
      const { eq } = await import("drizzle-orm");

      await db.update(users).set({
        deletedAt: new Date(),
        scheduledDeletionDate,
        deletionReason: "User requested deletion",
        updatedAt: new Date(),
      }).where(eq(users.id, userId));

      // Send confirmation email
      try {
        const { sendAccountDeletionEmail } = await import("./services/emailService");
        await sendAccountDeletionEmail(
          user.email,
          user.firstName || "User",
          scheduledDeletionDate,
          gracePeriodStart > new Date() ? gracePeriodStart : null
        );
      } catch (emailError) {
        console.error("Failed to send account deletion email:", emailError);
        // Don't fail the deletion if email fails
      }

      res.json({ 
        success: true, 
        message: "Your account has been scheduled for deletion.",
        scheduledDeletionDate,
        gracePeriodStart: gracePeriodStart > new Date() ? gracePeriodStart : new Date(),
      });
    } catch (error) {
      console.error("Error deleting account:", error);
      res.status(500).json({ error: "Failed to delete account" });
    }
  });

  // Get OAuth URL for external storage provider
  app.get("/api/storage/oauth/:provider", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      const provider = req.params.provider as "google_drive" | "dropbox" | "box";
      if (!["google_drive", "dropbox", "box"].includes(provider)) {
        return res.status(400).json({ error: "Invalid provider" });
      }

      const { generateOAuthUrl, isProviderConfigured } = await import("./services/externalStorage");
      
      if (!isProviderConfigured(provider)) {
        return res.status(400).json({ 
          error: `${provider} is not configured. Please add the required API credentials.` 
        });
      }

      const state = Buffer.from(JSON.stringify({ userId, provider })).toString("base64");
      const authUrl = generateOAuthUrl(provider, state);

      if (!authUrl) {
        return res.status(500).json({ error: "Failed to generate OAuth URL" });
      }

      res.json({ authUrl });
    } catch (error) {
      console.error("Error generating OAuth URL:", error);
      res.status(500).json({ error: "Failed to generate OAuth URL" });
    }
  });

  // OAuth callback handler
  app.get("/api/storage/oauth/callback/:provider", async (req: Request, res: Response) => {
    try {
      const provider = req.params.provider as "google_drive" | "dropbox" | "box";
      const { code, state } = req.query;

      if (!code || !state) {
        return res.redirect("/storage-settings?error=missing_params");
      }

      let stateData: { userId: string; provider: string };
      try {
        stateData = JSON.parse(Buffer.from(state as string, "base64").toString());
      } catch {
        return res.redirect("/storage-settings?error=invalid_state");
      }

      if (stateData.provider !== provider) {
        return res.redirect("/storage-settings?error=provider_mismatch");
      }

      const { 
        exchangeCodeForTokens, 
        encryptToken, 
        getUserInfoFromProvider 
      } = await import("./services/externalStorage");

      const tokens = await exchangeCodeForTokens(provider, code as string);
      if (!tokens) {
        return res.redirect("/storage-settings?error=token_exchange_failed");
      }

      const userInfo = await getUserInfoFromProvider(provider, tokens.access_token);

      await authStorage.saveStorageCredential({
        userId: stateData.userId,
        provider,
        accessTokenEncrypted: encryptToken(tokens.access_token, stateData.userId),
        refreshTokenEncrypted: tokens.refresh_token ? encryptToken(tokens.refresh_token, stateData.userId) : null,
        tokenExpiresAt: tokens.expires_in 
          ? new Date(Date.now() + tokens.expires_in * 1000) 
          : null,
        providerUserId: userInfo?.userId || null,
        providerEmail: userInfo?.email || null,
        folderPath: null,
        isActive: true,
      });

      res.redirect(`/storage-settings?success=connected&provider=${provider}`);
    } catch (error) {
      console.error("OAuth callback error:", error);
      res.redirect("/storage-settings?error=callback_failed");
    }
  });

  // Disconnect external storage provider
  app.delete("/api/storage/oauth/:provider", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      const provider = req.params.provider;
      if (!["google_drive", "dropbox", "box"].includes(provider)) {
        return res.status(400).json({ error: "Invalid provider" });
      }

      // Check if this is the current storage provider
      const user = await authStorage.getUser(userId);
      if (user?.storageProvider === provider) {
        // Switch to fairsign before disconnecting
        await authStorage.updateStorageProvider(userId, "fairsign");
      }

      await authStorage.deleteStorageCredential(userId, provider);
      res.json({ success: true });
    } catch (error) {
      console.error("Error disconnecting provider:", error);
      res.status(500).json({ error: "Failed to disconnect provider" });
    }
  });

  // Test Dropbox connection
  app.post("/api/storage/test/dropbox", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      // Check if user is Pro
      const user = await authStorage.getUser(userId);
      if (!user || (user.accountType !== "pro" && user.accountType !== "enterprise")) {
        return res.status(403).json({ error: "Dropbox storage is a Pro feature" });
      }

      // Get Dropbox credentials
      const creds = await authStorage.getStorageCredentials(userId, "dropbox");
      if (!creds || !creds.accessTokenEncrypted) {
        return res.status(400).json({ error: "Dropbox not connected. Please connect your Dropbox account first." });
      }

      const { decryptToken } = await import("./services/externalStorage");
      const accessToken = decryptToken(creds.accessTokenEncrypted, userId);

      // Test by getting account info (requires account_info.read scope)
      const accountResponse = await fetch("https://api.dropboxapi.com/2/users/get_current_account", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${accessToken}`,
        },
      });

      if (!accountResponse.ok) {
        const errorText = await accountResponse.text();
        console.error("[Dropbox Test] Account info failed:", errorText);
        
        // Check for specific scope errors
        if (errorText.includes("files.content.write")) {
          return res.status(400).json({ 
            success: false, 
            error: "Missing 'files.content.write' permission. Please enable this scope in your Dropbox App Console and reconnect." 
          });
        }
        if (errorText.includes("files.content.read")) {
          return res.status(400).json({ 
            success: false, 
            error: "Missing 'files.content.read' permission. Please enable this scope in your Dropbox App Console and reconnect." 
          });
        }
        
        return res.status(400).json({ 
          success: false, 
          error: `Dropbox authentication failed. Please disconnect and reconnect your Dropbox account.` 
        });
      }

      const accountInfo = await accountResponse.json();
      console.log("[Dropbox Test] Account info success:", accountInfo.email);

      // Test file write permission by uploading a small test file
      const testFileName = `/FairSign/.connection_test_${Date.now()}.txt`;
      const testContent = `FairSign connection test - ${new Date().toISOString()}`;

      const uploadResponse = await fetch("https://content.dropboxapi.com/2/files/upload", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Dropbox-API-Arg": JSON.stringify({
            path: testFileName,
            mode: "overwrite",
            autorename: false,
            mute: true,
          }),
          "Content-Type": "application/octet-stream",
        },
        body: testContent,
      });

      if (!uploadResponse.ok) {
        const errorText = await uploadResponse.text();
        console.error("[Dropbox Test] Upload failed:", errorText);
        
        if (errorText.includes("files.content.write")) {
          return res.status(400).json({ 
            success: false, 
            error: "Missing 'files.content.write' permission. Please enable this scope in your Dropbox App Console (Permissions tab), click Submit, then disconnect and reconnect your Dropbox account to get new tokens." 
          });
        }
        
        return res.status(400).json({ 
          success: false, 
          error: `Write permission test failed: ${errorText}` 
        });
      }

      console.log("[Dropbox Test] Upload test successful");

      // Clean up test file
      try {
        await fetch("https://api.dropboxapi.com/2/files/delete_v2", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${accessToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ path: testFileName }),
        });
      } catch (cleanupError) {
        // Ignore cleanup errors
      }

      res.json({ 
        success: true, 
        message: `Connection successful! Connected as ${accountInfo.email}. FairSign can read and write files to your Dropbox.`,
        email: accountInfo.email,
      });
    } catch (error) {
      console.error("Error testing Dropbox connection:", error);
      res.status(500).json({ 
        success: false, 
        error: error instanceof Error ? error.message : "Failed to test Dropbox connection" 
      });
    }
  });

  // Test Box connection
  app.post("/api/storage/test/box", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      // Check if user is Pro
      const user = await authStorage.getUser(userId);
      if (!user || (user.accountType !== "pro" && user.accountType !== "enterprise")) {
        return res.status(403).json({ error: "Box storage is a Pro feature" });
      }

      // Get Box credentials
      const creds = await authStorage.getStorageCredentials(userId, "box");
      if (!creds || !creds.accessTokenEncrypted) {
        return res.status(400).json({ error: "Box not connected. Please connect your Box account first." });
      }

      const { decryptToken } = await import("./services/externalStorage");
      const accessToken = decryptToken(creds.accessTokenEncrypted, userId);

      // Test by getting user info
      const userResponse = await fetch("https://api.box.com/2.0/users/me", {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${accessToken}`,
        },
      });

      if (!userResponse.ok) {
        const errorText = await userResponse.text();
        console.error("[Box Test] User info failed:", errorText);
        return res.status(400).json({ 
          success: false, 
          error: `Box authentication failed. Please disconnect and reconnect your Box account.` 
        });
      }

      const userInfo = await userResponse.json();
      console.log("[Box Test] User info success:", userInfo.login);

      // Test folder creation/access
      const folderCheckResponse = await fetch("https://api.box.com/2.0/folders/0/items?fields=id,name,type", {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${accessToken}`,
        },
      });

      if (!folderCheckResponse.ok) {
        const errorText = await folderCheckResponse.text();
        console.error("[Box Test] Folder access failed:", errorText);
        return res.status(400).json({ 
          success: false, 
          error: `Failed to access Box folders. Please check permissions.` 
        });
      }

      // Check if FairSign folder exists, create if not
      const folderData = await folderCheckResponse.json();
      let fairSignFolderId = folderData.entries?.find(
        (item: any) => item.type === "folder" && item.name === "FairSign"
      )?.id;

      if (!fairSignFolderId) {
        // Create FairSign folder
        const createFolderResponse = await fetch("https://api.box.com/2.0/folders", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${accessToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            name: "FairSign",
            parent: { id: "0" },
          }),
        });

        if (createFolderResponse.ok) {
          const newFolder = await createFolderResponse.json();
          fairSignFolderId = newFolder.id;
          console.log("[Box Test] Created FairSign folder:", fairSignFolderId);
        } else if (createFolderResponse.status === 409) {
          // Folder already exists (race condition), extract ID from conflict
          const conflictData = await createFolderResponse.json();
          fairSignFolderId = conflictData.context_info?.conflicts?.[0]?.id;
        }
      }

      console.log("[Box Test] FairSign folder ready:", fairSignFolderId);

      res.json({ 
        success: true, 
        message: `Connection successful! Connected as ${userInfo.login}. FairSign folder is ready in your Box.`,
        email: userInfo.login,
      });
    } catch (error) {
      console.error("Error testing Box connection:", error);
      res.status(500).json({ 
        success: false, 
        error: error instanceof Error ? error.message : "Failed to test Box connection" 
      });
    }
  });

  // ============ CUSTOM S3 STORAGE ENDPOINTS ============

  // Get user's custom S3 credentials (masked)
  app.get("/api/storage/custom-s3", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      // Check if user is Pro
      const user = await authStorage.getUser(userId);
      if (!user || (user.accountType !== "pro" && user.accountType !== "enterprise")) {
        return res.status(403).json({ error: "Custom S3 storage is a Pro feature" });
      }

      const { decryptToken } = await import("./services/externalStorage");
      const creds = await authStorage.getUserS3Credentials(userId);
      
      if (!creds) {
        return res.json({ configured: false });
      }

      // Return masked credentials
      res.json({
        configured: true,
        endpoint: decryptToken(creds.endpointEncrypted, userId),
        bucket: decryptToken(creds.bucketEncrypted, userId),
        accessKeyId: "••••••••" + decryptToken(creds.accessKeyIdEncrypted, userId).slice(-4),
        region: creds.region || "auto",
        prefix: creds.prefix || "",
        label: creds.label || "",
        lastTestedAt: creds.lastTestedAt,
      });
    } catch (error) {
      console.error("Error fetching custom S3 credentials:", error);
      res.status(500).json({ error: "Failed to fetch custom S3 credentials" });
    }
  });

  // Save user's custom S3 credentials
  app.post("/api/storage/custom-s3", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      // Check if user is Pro
      const user = await authStorage.getUser(userId);
      if (!user || (user.accountType !== "pro" && user.accountType !== "enterprise")) {
        return res.status(403).json({ error: "Custom S3 storage is a Pro feature" });
      }

      const { endpoint, bucket, accessKeyId, secretAccessKey, region, prefix, label } = req.body;
      
      if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) {
        return res.status(400).json({ error: "Endpoint, bucket, access key ID, and secret access key are required" });
      }

      const { encryptToken } = await import("./services/externalStorage");

      await authStorage.saveUserS3Credentials({
        userId,
        endpointEncrypted: encryptToken(endpoint, userId),
        bucketEncrypted: encryptToken(bucket, userId),
        accessKeyIdEncrypted: encryptToken(accessKeyId, userId),
        secretAccessKeyEncrypted: encryptToken(secretAccessKey, userId),
        region: region || "auto",
        prefix: prefix || null,
        label: label || null,
        isActive: true,
        lastTestedAt: null,
      });

      res.json({ success: true });
    } catch (error) {
      console.error("Error saving custom S3 credentials:", error);
      res.status(500).json({ error: "Failed to save custom S3 credentials" });
    }
  });

  // Test user's custom S3 credentials
  app.post("/api/storage/custom-s3/test", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      // Check if user is Pro
      const user = await authStorage.getUser(userId);
      if (!user || (user.accountType !== "pro" && user.accountType !== "enterprise")) {
        return res.status(403).json({ error: "Custom S3 storage is a Pro feature" });
      }

      const { endpoint, bucket, accessKeyId, secretAccessKey, region } = req.body;
      
      if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) {
        return res.status(400).json({ error: "All credentials are required for testing" });
      }

      // Test the connection
      const { S3Client, ListObjectsV2Command, PutObjectCommand, DeleteObjectCommand } = await import("@aws-sdk/client-s3");
      
      const client = new S3Client({
        endpoint,
        region: region || "auto",
        credentials: {
          accessKeyId,
          secretAccessKey,
        },
        forcePathStyle: true,
      });

      // Test list (read access)
      try {
        await client.send(new ListObjectsV2Command({ Bucket: bucket, MaxKeys: 1 }));
      } catch (e: any) {
        return res.status(400).json({ error: `Failed to list objects: ${e.message}` });
      }

      // Test upload (write access)
      const testKey = `fairsign-test-${Date.now()}.txt`;
      try {
        await client.send(new PutObjectCommand({
          Bucket: bucket,
          Key: testKey,
          Body: "FairSign connection test",
          ContentType: "text/plain",
        }));
      } catch (e: any) {
        return res.status(400).json({ error: `Failed to upload test file: ${e.message}` });
      }

      // Cleanup test file
      try {
        await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: testKey }));
      } catch (e) {
        // Ignore delete errors
      }

      // Update last tested timestamp if credentials are saved
      const existingCreds = await authStorage.getUserS3Credentials(userId);
      if (existingCreds) {
        await authStorage.updateUserS3LastTested(userId);
      }

      res.json({ success: true, message: "Connection test passed" });
    } catch (error: any) {
      console.error("Error testing custom S3 credentials:", error);
      res.status(500).json({ error: `Connection test failed: ${error.message}` });
    }
  });

  // Delete user's custom S3 credentials
  app.delete("/api/storage/custom-s3", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      // Check if this is the current storage provider
      const user = await authStorage.getUser(userId);
      if (user?.storageProvider === "custom_s3") {
        // Switch to fairsign before deleting
        await authStorage.updateStorageProvider(userId, "fairsign");
      }

      await authStorage.deleteUserS3Credentials(userId);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting custom S3 credentials:", error);
      res.status(500).json({ error: "Failed to delete custom S3 credentials" });
    }
  });

  // ============ TEMPLATE ENDPOINTS ============

  // Get all templates for authenticated user (includes default templates and team templates)
  app.get("/api/admin/templates", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      // Get accessible user IDs (self + team members)
      const accessibleUserIds = await getAccessibleUserIds(userId);
      
      // Fetch templates from all accessible users
      let allTemplates: any[] = [];
      const seenIds = new Set<string>();
      
      for (const uid of accessibleUserIds) {
        const templates = await storage.getTemplatesForUser(uid);
        for (const t of templates) {
          if (!seenIds.has(t.id)) {
            seenIds.add(t.id);
            allTemplates.push(t);
          }
        }
      }
      
      res.json(allTemplates);
    } catch (error) {
      console.error("Error fetching templates:", error);
      res.status(500).json({ error: "Failed to fetch templates" });
    }
  });

  // Get single template
  app.get("/api/admin/templates/:id", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      const templateId = req.params.id;

      const template = await storage.getTemplate(templateId);
      if (!template) {
        return res.status(404).json({ error: "Template not found" });
      }

      // Allow access if user owns template, it's a default template, or user is in same team
      const hasAccess = await canAccessTemplate(userId, template.userId, template.isDefault);
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied" });
      }

      res.json(template);
    } catch (error) {
      console.error("Error fetching template:", error);
      res.status(500).json({ error: "Failed to fetch template" });
    }
  });

  // Create new template
  app.post("/api/admin/templates", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      const { name, description, htmlContent, placeholders } = req.body;

      if (!name || !htmlContent) {
        return res.status(400).json({ error: "Name and HTML content are required" });
      }

      // Extract placeholders from HTML if not provided
      const extractedPlaceholders = placeholders || extractPlaceholders(htmlContent);

      const template = await storage.createTemplate({
        userId,
        name,
        description: description || null,
        htmlContent,
        placeholders: extractedPlaceholders,
        isDefault: false,
      });

      console.log(`Template created: ${template.id} by user ${userId}`);

      res.status(201).json(template);
    } catch (error) {
      console.error("Error creating template:", error);
      res.status(500).json({ error: "Failed to create template" });
    }
  });

  // Update template
  app.patch("/api/admin/templates/:id", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      const templateId = req.params.id;

      const template = await storage.getTemplate(templateId);
      if (!template) {
        return res.status(404).json({ error: "Template not found" });
      }

      if (template.isDefault) {
        return res.status(403).json({ error: "Cannot edit default templates" });
      }

      // Only owner or team member can edit (not default templates)
      const hasAccess = await canAccessUserDocuments(userId, template.userId);
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied" });
      }

      const { name, description, htmlContent, placeholders } = req.body;

      const updates: any = {};
      if (name) updates.name = name;
      if (description !== undefined) updates.description = description;
      if (htmlContent) {
        updates.htmlContent = htmlContent;
        updates.placeholders = placeholders || extractPlaceholders(htmlContent);
      }

      const updatedTemplate = await storage.updateTemplate(templateId, updates);

      res.json(updatedTemplate);
    } catch (error) {
      console.error("Error updating template:", error);
      res.status(500).json({ error: "Failed to update template" });
    }
  });

  // Delete template
  app.delete("/api/admin/templates/:id", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      const templateId = req.params.id;

      const template = await storage.getTemplate(templateId);
      if (!template) {
        return res.status(404).json({ error: "Template not found" });
      }

      // Cannot delete default templates
      if (template.isDefault) {
        return res.status(403).json({ error: "Cannot delete default templates" });
      }

      // Only owner or team member can delete templates
      const hasAccess = await canAccessUserDocuments(userId, template.userId);
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied" });
      }

      await storage.deleteTemplate(templateId);

      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting template:", error);
      res.status(500).json({ error: "Failed to delete template" });
    }
  });

  // Upload PDF template
  app.post("/api/admin/templates/pdf", isAuthenticated, upload.single("pdf"), async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      const file = req.file;
      if (!file) {
        return res.status(400).json({ error: "PDF file is required" });
      }

      if (!file.mimetype.includes("pdf")) {
        return res.status(400).json({ error: "File must be a PDF" });
      }

      const { name, description } = req.body;
      if (!name) {
        return res.status(400).json({ error: "Template name is required" });
      }

      // Extract page info using pdf-lib
      const { PDFDocument } = await import("pdf-lib");
      const pdfDoc = await PDFDocument.load(file.buffer);
      const pageCount = pdfDoc.getPageCount();
      const pageDimensions: { width: number; height: number }[] = [];

      for (let i = 0; i < pageCount; i++) {
        const page = pdfDoc.getPage(i);
        const { width, height } = page.getSize();
        pageDimensions.push({ width, height });
      }

      // Upload PDF to object storage
      const templateId = nanoid();
      const pdfKey = `templates/${templateId}/original.pdf`;
      const pdfStorageKey = await objectStorage.uploadBuffer(file.buffer, pdfKey, "application/pdf");

      // Create template record
      const template = await storage.createTemplate({
        userId,
        name,
        description: description || null,
        templateType: "pdf",
        htmlContent: null,
        pdfStorageKey,
        pageCount,
        pageDimensions,
        placeholders: [],
        isDefault: false,
      });

      console.log(`PDF template created: ${template.id} with ${pageCount} pages`);

      res.status(201).json(template);
    } catch (error) {
      console.error("Error uploading PDF template:", error);
      res.status(500).json({ error: "Failed to upload PDF template" });
    }
  });

  // Get template fields
  app.get("/api/admin/templates/:id/fields", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      const templateId = req.params.id;

      const template = await storage.getTemplate(templateId);
      if (!template) {
        return res.status(404).json({ error: "Template not found" });
      }

      // Allow access if user owns template, it's a default template, or user is in same team
      const hasAccess = await canAccessTemplate(userId, template.userId, template.isDefault);
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied" });
      }

      const fields = await storage.getTemplateFields(templateId);
      res.json(fields);
    } catch (error) {
      console.error("Error fetching template fields:", error);
      res.status(500).json({ error: "Failed to fetch template fields" });
    }
  });

  // Save template fields (replace all)
  app.put("/api/admin/templates/:id/fields", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      const templateId = req.params.id;

      const template = await storage.getTemplate(templateId);
      if (!template) {
        return res.status(404).json({ error: "Template not found" });
      }

      if (template.isDefault) {
        return res.status(403).json({ error: "Cannot edit default templates" });
      }

      // Only owner or team member can edit
      const hasAccess = await canAccessUserDocuments(userId, template.userId);
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (template.templateType !== "pdf") {
        return res.status(400).json({ error: "Fields can only be added to PDF templates" });
      }

      const { fields, signerRoles } = req.body;
      if (!Array.isArray(fields)) {
        return res.status(400).json({ error: "Fields must be an array" });
      }

      // Delete existing fields
      await storage.deleteTemplateFields(templateId);

      // Create new fields
      const createdFields = [];
      for (const field of fields) {
        const created = await storage.createTemplateField({
          templateId,
          apiTag: field.apiTag,
          fieldType: field.fieldType,
          label: field.label || null,
          page: field.page,
          x: field.x,
          y: field.y,
          width: field.width,
          height: field.height,
          signerRole: field.signerRole || "tenant",
          required: field.required !== false,
          fontSize: field.fontSize || 12,
          fontColor: field.fontColor || "#000000",
          inputMode: field.inputMode || "any",
          placeholder: field.placeholder || null,
          creatorFills: field.creatorFills || false,
        });
        createdFields.push(created);
      }

      // Update template placeholders and signer roles
      const placeholders = createdFields.map(f => f.apiTag);
      const updateData: any = { placeholders };
      if (Array.isArray(signerRoles) && signerRoles.length > 0) {
        updateData.signerRoles = signerRoles;
      }
      await storage.updateTemplate(templateId, updateData);

      res.json(createdFields);
    } catch (error) {
      console.error("Error saving template fields:", error);
      res.status(500).json({ error: "Failed to save template fields" });
    }
  });

  // Get PDF preview URL (legacy - returns S3 URL which may have CORS issues)
  app.get("/api/admin/templates/:id/pdf-url", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      const templateId = req.params.id;

      const template = await storage.getTemplate(templateId);
      if (!template) {
        return res.status(404).json({ error: "Template not found" });
      }

      // Allow access if user owns template, it's a default template, or user is in same team
      const hasAccess = await canAccessTemplate(userId, template.userId, template.isDefault);
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (template.templateType !== "pdf" || !template.pdfStorageKey) {
        return res.status(400).json({ error: "Template is not a PDF template" });
      }

      const url = await objectStorage.getSignedDownloadUrl(template.pdfStorageKey, 3600);
      res.json({ url });
    } catch (error) {
      console.error("Error getting PDF URL:", error);
      res.status(500).json({ error: "Failed to get PDF URL" });
    }
  });

  // Proxy PDF template - streams PDF through backend to avoid CORS issues
  app.get("/api/admin/templates/:id/pdf", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      const templateId = req.params.id;

      const template = await storage.getTemplate(templateId);
      if (!template) {
        return res.status(404).json({ error: "Template not found" });
      }

      // Allow access if user owns template, it's a default template, or user is in same team
      const hasAccess = await canAccessTemplate(userId, template.userId, template.isDefault);
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (template.templateType !== "pdf" || !template.pdfStorageKey) {
        return res.status(400).json({ error: "Template is not a PDF template" });
      }

      // Download PDF from storage and stream to client
      const privateDir = objectStorage.getPrivateObjectDir();
      const pdfPath = joinStoragePath(privateDir, template.pdfStorageKey);
      const pdfBuffer = await objectStorage.downloadBuffer(pdfPath);

      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Length", pdfBuffer.length);
      res.setHeader("Cache-Control", "private, max-age=3600");
      res.send(pdfBuffer);
    } catch (error) {
      console.error("Error streaming PDF:", error);
      res.status(500).json({ error: "Failed to stream PDF" });
    }
  });

  // Get template metadata for external API integration
  app.get("/api/templates/:id/metadata", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      const templateId = req.params.id;

      const template = await storage.getTemplate(templateId);
      if (!template) {
        return res.status(404).json({ error: "Template not found" });
      }

      // Allow access if user owns template, it's a default template, or user is in same team
      const hasAccess = await canAccessTemplate(userId, template.userId, template.isDefault);
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied" });
      }

      const metadata: {
        id: string;
        name: string;
        description: string | null;
        templateType: string;
        pageCount: number | null;
        fields: {
          apiTag: string;
          fieldType: string;
          label: string | null;
          page: number;
          signerRole: string | null;
          required: boolean;
        }[];
        placeholders: string[];
      } = {
        id: template.id,
        name: template.name,
        description: template.description,
        templateType: template.templateType || "html",
        pageCount: template.pageCount,
        fields: [],
        placeholders: (template.placeholders as string[]) || [],
      };

      if (template.templateType === "pdf") {
        const fields = await storage.getTemplateFields(templateId);
        metadata.fields = fields.map((f) => ({
          apiTag: f.apiTag,
          fieldType: f.fieldType,
          label: f.label,
          page: f.page,
          signerRole: f.signerRole,
          required: f.required ?? true,
        }));
      }

      res.json(metadata);
    } catch (error) {
      console.error("Error getting template metadata:", error);
      res.status(500).json({ error: "Failed to get template metadata" });
    }
  });

  // ===== Email Notification Endpoints =====

  // Test email endpoint (development only)
  app.post("/api/test-email", async (req: Request, res: Response) => {
    try {
      const { toEmail, toName } = req.body;
      if (!toEmail) {
        return res.status(400).json({ error: "toEmail is required" });
      }
      
      const { sendEmail } = await import("./services/emailService");
      const { FAIRSIGN_LOGO_SVG } = await import("./services/fairsignLogo");
      const currentYear = new Date().getFullYear();
      const signerName = toName || "Test User";
      const documentTitle = "Test Document - Lease Agreement";
      const signingUrl = `${process.env.BASE_URL || "https://example.com"}/sign/test`;
      
      const htmlBody = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; background-color: #ffffff; }
    .wrapper { width: 100%; background-color: #ffffff; padding: 40px 20px; }
    .container { max-width: 580px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    .header { background-color: #ffffff; padding: 32px 40px; text-align: center; border-bottom: 1px solid #e9ecef; }
    .content { padding: 40px; }
    .greeting { font-size: 22px; font-weight: 600; margin: 0 0 24px 0; }
    .message { font-size: 16px; color: #4a4a4a; margin: 0 0 16px 0; }
    .button { display: inline-block; background: linear-gradient(135deg, #0066cc 0%, #004499 100%); color: #ffffff; padding: 16px 40px; text-decoration: none; border-radius: 6px; font-weight: 600; }
    .footer { background-color: #f8f9fa; padding: 24px 40px; text-align: center; border-top: 1px solid #e9ecef; }
    .footer-text { font-size: 12px; color: #6c757d; margin: 0 0 8px 0; }
    .footer-legal { font-size: 11px; color: #868e96; margin: 16px 0 0 0; }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="container">
      <div class="header">
        <div style="background-color: #ffffff; display: inline-block; padding: 8px; border-radius: 4px;">
          ${FAIRSIGN_LOGO_SVG}
        </div>
      </div>
      <div class="content">
        <h1 class="greeting">Hello ${signerName},</h1>
        <p class="message">You have been requested to sign a document. Please review and sign at your earliest convenience.</p>
        <div style="margin: 24px 0; padding: 16px; background: #f8f9fa; border-radius: 6px;">
          <p style="font-size: 13px; color: #6c757d; margin: 0 0 4px 0;">Document</p>
          <p style="font-size: 16px; font-weight: 600; margin: 0;">${documentTitle}</p>
        </div>
        <div style="text-align: center; margin: 32px 0;">
          <a href="${signingUrl}" class="button">Review &amp; Sign Document</a>
        </div>
        <p class="message">If you have any questions about this document, please contact the sender or email <a href="mailto:support@fairsign.io">support@fairsign.io</a>.</p>
      </div>
      <div class="footer">
        <p class="footer-text">This is an automated message from FairSign.io. Please do not reply to this email.</p>
        <p class="footer-legal">&copy; ${currentYear} FairSign.io. All Rights Reserved.<br>Unauthorised use is prohibited by law.</p>
      </div>
    </div>
  </div>
</body>
</html>`.trim();
      
      const result = await sendEmail({
        emailType: "signature_request",
        toEmail,
        toName: signerName,
        subject: `Action Required: ${signerName}, please sign "${documentTitle}"`,
        htmlBody,
      });
      
      res.json({ success: result.success, emailLogId: result.emailLogId, error: result.error });
    } catch (error) {
      console.error("Error sending test email:", error);
      res.status(500).json({ error: "Failed to send test email" });
    }
  });

  // Send signature request email for a document
  app.post("/api/admin/documents/:id/send-email", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      const documentId = req.params.id;
      const { signerEmail, signerName } = req.body;

      if (!signerEmail) {
        return res.status(400).json({ error: "signerEmail is required" });
      }

      const document = await storage.getDocument(documentId);
      if (!document) {
        return res.status(404).json({ error: "Document not found" });
      }

      // Verify ownership or team membership
      const hasAccess = await canAccessUserDocuments(userId, document.userId);
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (document.status === "completed") {
        return res.status(400).json({ error: "Document already completed" });
      }

      const result = await sendSignatureRequestEmail(document, signerEmail, signerName);

      if (!result.success) {
        return res.status(500).json({ error: result.error || "Failed to send email" });
      }

      await storage.updateDocument(documentId, { status: "sent" });

      await logAuditEvent(documentId, "email_sent", req, {
        emailType: "signature_request",
        recipientEmail: signerEmail,
        emailLogId: result.emailLogId,
      });

      res.json({ 
        success: true, 
        message: "Signature request email sent",
        emailLogId: result.emailLogId 
      });
    } catch (error) {
      console.error("Error sending signature request email:", error);
      res.status(500).json({ error: "Failed to send email" });
    }
  });

  // Send reminder email for a document
  app.post("/api/admin/documents/:id/send-reminder", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      const documentId = req.params.id;
      const { signerEmail, signerName } = req.body;

      if (!signerEmail) {
        return res.status(400).json({ error: "signerEmail is required" });
      }

      const document = await storage.getDocument(documentId);
      if (!document) {
        return res.status(404).json({ error: "Document not found" });
      }

      // Verify ownership or team membership
      const hasAccess = await canAccessUserDocuments(userId, document.userId);
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied" });
      }

      if (document.status === "completed") {
        return res.status(400).json({ error: "Document already completed" });
      }

      const result = await sendReminderEmail(document, signerEmail, signerName);

      if (!result.success) {
        return res.status(500).json({ error: result.error || "Failed to send reminder" });
      }

      await logAuditEvent(documentId, "reminder_sent", req, {
        emailType: "reminder",
        recipientEmail: signerEmail,
        emailLogId: result.emailLogId,
      });

      res.json({ 
        success: true, 
        message: "Reminder email sent",
        emailLogId: result.emailLogId 
      });
    } catch (error) {
      console.error("Error sending reminder email:", error);
      res.status(500).json({ error: "Failed to send reminder" });
    }
  });

  // Get email logs for a document
  app.get("/api/admin/documents/:id/emails", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      const documentId = req.params.id;

      const document = await storage.getDocument(documentId);
      if (!document) {
        return res.status(404).json({ error: "Document not found" });
      }

      // Verify ownership or team membership
      const hasAccess = await canAccessUserDocuments(userId, document.userId);
      if (!hasAccess) {
        return res.status(403).json({ error: "Access denied" });
      }

      const emails = await getEmailLogsForDocument(documentId);

      res.json(emails);
    } catch (error) {
      console.error("Error fetching email logs:", error);
      res.status(500).json({ error: "Failed to fetch email logs" });
    }
  });

  // ========== SIGNER SESSION ROUTES (QR Code Mobile Signing) ==========

  // Create a signer session for mobile signing
  app.post("/api/signer-sessions", async (req: Request, res: Response) => {
    try {
      const { documentId, signerId, spotKey } = req.body;

      if (!documentId || !signerId || !spotKey) {
        return res.status(400).json({ error: "Missing required fields" });
      }

      const signer = await storage.getDocumentSignerById(signerId);
      if (!signer) {
        return res.status(404).json({ error: "Signer not found" });
      }

      if (signer.documentId !== documentId) {
        return res.status(403).json({ error: "Signer does not belong to this document" });
      }

      // Generate a unique session token
      const sessionToken = nanoid(32);
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

      const session = await storage.createSignerSession({
        documentId,
        signerId,
        sessionToken,
        spotKey,
        status: "pending",
        expiresAt,
      });

      res.json({
        sessionToken: session.sessionToken,
        expiresAt: session.expiresAt,
      });
    } catch (error) {
      console.error("Error creating signer session:", error);
      res.status(500).json({ error: "Failed to create signer session" });
    }
  });

  // Verify a signer session (for mobile page)
  app.get("/api/signer-sessions/:sessionToken/verify", async (req: Request, res: Response) => {
    try {
      const { sessionToken } = req.params;

      const session = await storage.getSignerSession(sessionToken);
      if (!session) {
        return res.status(404).json({ error: "Session not found" });
      }

      if (session.status === "completed") {
        return res.status(400).json({ error: "Session already completed" });
      }

      if (new Date() > session.expiresAt) {
        await storage.updateSignerSession(session.id, { status: "expired" });
        return res.status(400).json({ error: "Session expired" });
      }

      const document = await storage.getDocument(session.documentId);
      const signer = await storage.getDocumentSignerById(session.signerId);

      res.json({
        valid: true,
        documentTitle: (document?.dataJson as any)?.title || "Document",
        signerName: signer?.name || "Signer",
        spotKey: session.spotKey,
      });
    } catch (error) {
      console.error("Error verifying signer session:", error);
      res.status(500).json({ error: "Failed to verify session" });
    }
  });

  // Check session status (for desktop polling)
  app.get("/api/signer-sessions/:sessionToken/status", async (req: Request, res: Response) => {
    try {
      const { sessionToken } = req.params;

      const session = await storage.getSignerSession(sessionToken);
      if (!session) {
        return res.status(404).json({ error: "Session not found" });
      }

      // Check if expired
      if (session.status === "pending" && new Date() > session.expiresAt) {
        await storage.updateSignerSession(session.id, { status: "expired" });
        return res.json({ status: "expired" });
      }

      res.json({ status: session.status });
    } catch (error) {
      console.error("Error checking session status:", error);
      res.status(500).json({ error: "Failed to check session status" });
    }
  });

  // Submit signature from mobile device
  app.post("/api/signer-sessions/:sessionToken/submit", upload.single("signature"), async (req: Request, res: Response) => {
    try {
      const { sessionToken } = req.params;
      const file = req.file;

      if (!file) {
        return res.status(400).json({ error: "No signature file provided" });
      }

      const session = await storage.getSignerSession(sessionToken);
      if (!session) {
        return res.status(404).json({ error: "Session not found" });
      }

      if (session.status === "completed") {
        return res.status(400).json({ error: "Session already completed" });
      }

      if (new Date() > session.expiresAt) {
        await storage.updateSignerSession(session.id, { status: "expired" });
        return res.status(400).json({ error: "Session expired" });
      }

      const signer = await storage.getDocumentSignerById(session.signerId);
      if (!signer) {
        return res.status(404).json({ error: "Signer not found" });
      }

      // Upload signature to object storage
      const privateDir = objectStorage.getPrivateObjectDir();
      const imageKey = `documents/${session.documentId}/signatures/${session.spotKey}.png`;
      const fullPath = joinStoragePath(privateDir, imageKey);
      await objectStorage.uploadBuffer(file.buffer, fullPath, "image/png");

      // Create signature asset
      await storage.createSignatureAsset({
        documentId: session.documentId,
        spotKey: session.spotKey,
        imageKey,
        signerRole: signer.role,
        signerEmail: signer.email,
      });

      // Mark session as completed
      await storage.updateSignerSession(session.id, {
        status: "completed",
        completedAt: new Date(),
      });

      // Log audit event
      await logAuditEvent(session.documentId, "signature_uploaded", req, {
        spotKey: session.spotKey,
        signerEmail: signer.email,
        signerRole: signer.role,
        source: "mobile_qr",
      });

      res.json({ success: true });
    } catch (error) {
      console.error("Error submitting mobile signature:", error);
      res.status(500).json({ error: "Failed to submit signature" });
    }
  });

  // ===== EMBEDDED SIGNING API (Enterprise Feature) =====
  
  // Get allowed origins for embedded signing
  app.get("/api/embedded/allowed-origins", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }
      
      const user = await authStorage.getUser(userId);
      if (!user || user.accountType !== "enterprise") {
        return res.status(403).json({
          error: "Enterprise subscription required",
          message: "Embedded signing is an Enterprise feature.",
        });
      }
      
      res.json({ allowedOrigins: user.allowedOrigins || [] });
    } catch (error) {
      console.error("Error fetching allowed origins:", error);
      res.status(500).json({ error: "Failed to fetch allowed origins" });
    }
  });
  
  // Update allowed origins for embedded signing
  app.put("/api/embedded/allowed-origins", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }
      
      const user = await authStorage.getUser(userId);
      if (!user || user.accountType !== "enterprise") {
        return res.status(403).json({
          error: "Enterprise subscription required",
          message: "Embedded signing is an Enterprise feature.",
        });
      }
      
      const { origins } = req.body;
      if (!Array.isArray(origins)) {
        return res.status(400).json({ error: "origins must be an array" });
      }
      
      // Validate origins are valid URLs
      const validOrigins: string[] = [];
      for (const origin of origins) {
        if (typeof origin !== "string") continue;
        try {
          const url = new URL(origin);
          // Only allow https (or http for localhost)
          if (url.protocol === "https:" || (url.protocol === "http:" && url.hostname === "localhost")) {
            validOrigins.push(url.origin); // Normalize to origin only
          }
        } catch {
          // Skip invalid URLs
        }
      }
      
      await authStorage.updateAllowedOrigins(userId, validOrigins);
      res.json({ success: true, allowedOrigins: validOrigins });
    } catch (error) {
      console.error("Error updating allowed origins:", error);
      res.status(500).json({ error: "Failed to update allowed origins" });
    }
  });
  
  // Create embedded signing session (silent - no email sent)
  // Embedded signing API - uses feature access middleware for API quota tracking
  app.post("/api/v1/embedded/sign-url", isAuthenticated, checkFeatureAccess("api_access"), async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }
      
      const user = await authStorage.getUser(userId);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      
      const { template_id, signer_email, signer_name, redirect_url } = req.body;
      
      if (!template_id) {
        return res.status(400).json({ error: "template_id is required" });
      }
      if (!signer_email) {
        return res.status(400).json({ error: "signer_email is required" });
      }
      if (!signer_name) {
        return res.status(400).json({ error: "signer_name is required" });
      }
      
      // Fetch template - first try templates table, then documents table with is_template=true
      console.log(`[Embedded] Looking up template_id: ${template_id} for userId: ${userId}`);
      
      let template = await storage.getTemplate(template_id);
      let isDocumentAsTemplate = false;
      
      // If not found in templates table, check documents table for is_template=true records
      if (!template) {
        console.log(`[Embedded] Template not found in templates table, checking documents table...`);
        const doc = await storage.getDocument(template_id);
        console.log(`[Embedded] Document lookup result:`, doc ? { id: doc.id, isTemplate: (doc as any).isTemplate, userId: doc.userId, mimeType: (doc as any).mimeType } : 'not found');
        
        if (doc && (doc as any).isTemplate === true) {
          // Convert document to template-like object for downstream compatibility
          isDocumentAsTemplate = true;
          template = {
            id: doc.id,
            userId: doc.userId,
            name: (doc as any).title || 'Untitled',
            templateType: 'pdf',
            pdfKey: doc.unsignedPdfKey,
            pdfStorageKey: doc.unsignedPdfKey,
          } as any;
          console.log(`[Embedded] Found document as template:`, template);
        }
      }
      
      if (!template) {
        console.log(`[Embedded] Template not found in either table for id: ${template_id}`);
        return res.status(404).json({ error: "Template not found" });
      }
      
      // Check template ownership (allow null userId for shared templates)
      console.log(`[Embedded] Checking ownership: template.userId=${template.userId}, requestUserId=${userId}`);
      if (template.userId && template.userId !== userId) {
        return res.status(403).json({ error: "Template not accessible" });
      }
      
      // Check document usage limits
      const usage = await authStorage.checkDocumentUsage(userId);
      if (!usage.canCreate) {
        return res.status(403).json({
          error: "Document limit reached",
          message: `You have used ${usage.used} of ${usage.limit} documents this month.`,
        });
      }
      
      // Download template PDF
      let pdfBuffer: Buffer;
      const pdfKey = template.pdfKey || template.pdfStorageKey;
      console.log(`[Embedded] Template type: ${template.templateType}, pdfKey: ${pdfKey}`);
      
      if (template.templateType === "pdf" && pdfKey) {
        pdfBuffer = await objectStorage.downloadBuffer(pdfKey);
      } else {
        console.log(`[Embedded] PDF download failed - templateType: ${template.templateType}, pdfKey: ${pdfKey}`);
        return res.status(400).json({ error: "Only PDF templates are supported for embedded signing" });
      }
      
      // Calculate original document hash
      const originalHash = createHash("sha256").update(pdfBuffer).digest("hex");
      
      // Get storage context
      const storageContext = await resolveDocumentStorageContext(userId);
      
      // Upload PDF
      const unsignedPdfKey = `documents/${nanoid()}/unsigned.pdf`;
      await storageContext.backend.uploadBuffer(pdfBuffer, unsignedPdfKey, "application/pdf");
      
      // Generate signing token
      const signingToken = nanoid(32);
      
      // Create signer record
      const signerId = nanoid();
      const signerToken = nanoid(32);
      const signers = [{
        id: signerId,
        name: signer_name,
        email: signer_email,
        role: "signer",
        token: signerToken,
      }];
      
      // Get template fields
      const templateFields = await storage.getTemplateFields(template_id);
      
      // Build fields for document
      const fields = templateFields.map(field => ({
        id: field.id,
        signerId,
        fieldType: field.fieldType,
        page: field.page,
        x: field.x,
        y: field.y,
        width: field.width,
        height: field.height,
        required: field.required,
        apiTag: field.apiTag,
      }));
      
      // Create document
      const document = await storage.createDocument({
        templateId: template_id,
        title: template.name,
        isTemplate: false,
        mimeType: "application/pdf",
        unsignedPdfKey,
        originalHash,
        status: "pending",
        signingToken,
        userId,
        storageBucket: storageContext.storageBucket,
        storageRegion: storageContext.storageRegion,
        dataJson: {
          embeddedSigning: true,
          oneOffDocument: true,
          title: template.name,
          signers,
          fields,
          redirectUrl: redirect_url,
        },
      });
      
      // Log audit event
      await logAuditEvent(document.id, "embedded_session_created", req, { 
        template_id, 
        signer_email,
        userId,
      });
      
      // Increment document count
      await authStorage.incrementDocumentCount(userId);
      
      const baseUrl = process.env.BASE_URL || `https://${req.headers.host}`;
      const signingUrl = `${baseUrl}/d/${document.id}?token=${signerToken}`;
      
      console.log(`[Embedded] Document created: ${document.id} for ${signer_email}`);
      
      // Return URL without sending email (silent creation)
      res.status(201).json({
        url: signingUrl,
        document_id: document.id,
        expires_in: 86400 * 7, // 7 days in seconds
      });
    } catch (error) {
      console.error("[Embedded] Error creating sign URL:", error);
      res.status(500).json({ error: "Failed to create embedded signing session" });
    }
  });

  // ===== BULK SEND ROUTES =====

  // Step 1: Prepare bulk send - upload PDF and CSV, create draft batch (Enterprise only)
  app.post(
    "/api/bulk-send/prepare",
    isAuthenticated,
    checkFeatureAccess("bulk_send"),
    upload.fields([
      { name: "pdf", maxCount: 1 },
      { name: "csv", maxCount: 1 },
    ]),
    async (req: Request, res: Response) => {
      try {
        const userId = (req.user as any)?.id;
        if (!userId) {
          return res.status(401).json({ error: "User not authenticated" });
        }

        const user = await authStorage.getUser(userId);
        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }

        const files = req.files as { [fieldname: string]: Express.Multer.File[] };
        const pdfFile = files.pdf?.[0];
        const csvFile = files.csv?.[0];

        if (!pdfFile) {
          return res.status(400).json({ error: "PDF file is required" });
        }
        if (!csvFile) {
          return res.status(400).json({ error: "CSV file is required" });
        }

        const title = req.body.title || pdfFile.originalname.replace(/\.pdf$/i, "") || "Bulk Document";

        // Parse CSV
        const Papa = await import("papaparse");
        const csvContent = csvFile.buffer.toString("utf-8");
        const parseResult = Papa.default.parse<{ name: string; email: string }>(csvContent, {
          header: true,
          skipEmptyLines: true,
        });

        if (parseResult.errors.length > 0) {
          return res.status(400).json({
            error: "CSV parsing error",
            details: parseResult.errors.slice(0, 5),
          });
        }

        const recipients = parseResult.data.filter(
          (row) => row.name && row.email && row.email.includes("@")
        );

        if (recipients.length === 0) {
          return res.status(400).json({
            error: "No valid recipients found in CSV",
            message: "CSV must have 'name' and 'email' columns with valid data.",
          });
        }

        // Upload PDF to object storage
        const privateDir = objectStorage.getPrivateObjectDir();
        const pdfStorageKey = `bulk/${nanoid()}/template.pdf`;
        const fullPdfPath = joinStoragePath(privateDir, pdfStorageKey);
        await objectStorage.uploadBuffer(pdfFile.buffer, fullPdfPath, "application/pdf");

        // Create draft batch (not processing yet - awaiting field configuration)
        const batch = await storage.createBulkBatch({
          userId,
          originalFilename: pdfFile.originalname,
          title,
          pdfStorageKey: fullPdfPath,
          status: "draft",
        });

        // Create items for each recipient
        const items = recipients.map((recipient) => ({
          batchId: batch.id,
          recipientName: recipient.name,
          recipientEmail: recipient.email,
          status: "pending" as const,
          errorMessage: null,
          envelopeId: null,
        }));

        await storage.createBulkItems(items);

        console.log(`[BulkSend] Created draft batch ${batch.id} with ${recipients.length} recipients`);

        res.status(201).json({
          batchId: batch.id,
          recipientCount: recipients.length,
          status: "draft",
          message: `Draft created with ${recipients.length} recipients. Configure signature fields and send.`,
        });
      } catch (error) {
        console.error("Error creating bulk send draft:", error);
        res.status(500).json({ error: "Failed to create bulk send draft" });
      }
    }
  );

  // Get PDF for a draft batch (for field editor preview)
  app.get(
    "/api/bulk-batches/:id/pdf",
    isAuthenticated,
    async (req: Request, res: Response) => {
      try {
        const userId = (req.user as any)?.id;
        if (!userId) {
          return res.status(401).json({ error: "User not authenticated" });
        }

        const batch = await storage.getBulkBatch(req.params.id);
        if (!batch) {
          return res.status(404).json({ error: "Batch not found" });
        }

        if (batch.userId !== userId) {
          return res.status(403).json({ error: "Access denied" });
        }

        const pdfBuffer = await objectStorage.downloadBuffer(batch.pdfStorageKey);
        res.setHeader("Content-Type", "application/pdf");
        res.setHeader("Content-Disposition", `inline; filename="${batch.originalFilename}"`);
        res.send(pdfBuffer);
      } catch (error) {
        console.error("Error fetching batch PDF:", error);
        res.status(500).json({ error: "Failed to fetch PDF" });
      }
    }
  );

  // Step 2: Send bulk batch - save fields and start processing
  app.post(
    "/api/bulk-batches/:id/send",
    isAuthenticated,
    checkFeatureAccess("bulk_send"),
    async (req: Request, res: Response) => {
      try {
        const userId = (req.user as any)?.id;
        if (!userId) {
          return res.status(401).json({ error: "User not authenticated" });
        }

        const batch = await storage.getBulkBatch(req.params.id);
        if (!batch) {
          return res.status(404).json({ error: "Batch not found" });
        }

        if (batch.userId !== userId) {
          return res.status(403).json({ error: "Access denied" });
        }

        if (batch.status !== "draft") {
          return res.status(400).json({ error: "Batch has already been sent" });
        }

        const { fields } = req.body;
        
        // Validate that at least one signature field is defined
        if (!fields || !Array.isArray(fields) || fields.length === 0) {
          return res.status(400).json({ 
            error: "At least one signature field is required",
            message: "Please place at least one signature field on the document before sending.",
          });
        }

        const signatureFields = fields.filter((f: any) => f.fieldType === "signature");
        if (signatureFields.length === 0) {
          return res.status(400).json({ 
            error: "At least one signature field is required",
            message: "Please add a signature field so recipients know where to sign.",
          });
        }

        // Update batch with field definitions and set to processing
        await storage.updateBulkBatch(batch.id, { 
          fieldsJson: fields,
          status: "processing",
        });

        console.log(`[BulkSend] Starting batch ${batch.id} with ${fields.length} fields`);

        // Trigger background processing asynchronously
        setImmediate(async () => {
          try {
            const { processBulkBatch } = await import("./services/bulkProcessor");
            await processBulkBatch(batch.id);
          } catch (error) {
            console.error(`[BulkSend] Error processing batch ${batch.id}:`, error);
          }
        });

        const items = await storage.getBulkItems(batch.id);

        res.json({
          batchId: batch.id,
          recipientCount: items.length,
          status: "processing",
          message: `Sending to ${items.length} recipients. Processing started.`,
        });
      } catch (error) {
        console.error("Error sending bulk batch:", error);
        res.status(500).json({ error: "Failed to send bulk batch" });
      }
    }
  );

  // Legacy endpoint for backward compatibility - redirects to prepare flow
  app.post(
    "/api/bulk-send",
    isAuthenticated,
    checkFeatureAccess("bulk_send"),
    upload.fields([
      { name: "pdf", maxCount: 1 },
      { name: "csv", maxCount: 1 },
    ]),
    async (req: Request, res: Response) => {
      // Redirect to the new prepare endpoint
      return res.status(400).json({
        error: "Bulk send workflow updated",
        message: "Please use the new bulk send flow: 1) POST /api/bulk-send/prepare, 2) Configure fields, 3) POST /api/bulk-batches/:id/send",
      });
    }
  );

  // Get bulk send batches for the current user
  app.get("/api/bulk-batches", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      const batches = await storage.getBulkBatchesByUser(userId);

      // Get item counts for each batch
      const batchesWithStats = await Promise.all(
        batches.map(async (batch) => {
          const items = await storage.getBulkItems(batch.id);
          const sentCount = items.filter((i) => i.status === "sent").length;
          const errorCount = items.filter((i) => i.status === "error").length;
          const pendingCount = items.filter((i) => i.status === "pending").length;
          return {
            ...batch,
            totalCount: items.length,
            sentCount,
            errorCount,
            pendingCount,
          };
        })
      );

      res.json(batchesWithStats);
    } catch (error) {
      console.error("Error fetching bulk batches:", error);
      res.status(500).json({ error: "Failed to fetch bulk batches" });
    }
  });

  // Get details of a specific batch with its items
  app.get("/api/bulk-batches/:id", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const userId = (req.user as any)?.id;
      if (!userId) {
        return res.status(401).json({ error: "User not authenticated" });
      }

      const batchId = req.params.id;
      const batch = await storage.getBulkBatch(batchId);

      if (!batch) {
        return res.status(404).json({ error: "Batch not found" });
      }

      if (batch.userId !== userId) {
        return res.status(403).json({ error: "Access denied" });
      }

      const items = await storage.getBulkItems(batchId);

      res.json({
        ...batch,
        items,
        totalCount: items.length,
        sentCount: items.filter((i) => i.status === "sent").length,
        errorCount: items.filter((i) => i.status === "error").length,
        pendingCount: items.filter((i) => i.status === "pending").length,
      });
    } catch (error) {
      console.error("Error fetching bulk batch details:", error);
      res.status(500).json({ error: "Failed to fetch batch details" });
    }
  });

  // ===== USER GUIDES ROUTES =====
  
  // Public routes for logged-in users - get published guides
  app.get("/api/guides", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const guides = await storage.getPublishedUserGuides();
      res.json(guides);
    } catch (error) {
      console.error("Error fetching guides:", error);
      res.status(500).json({ error: "Failed to fetch guides" });
    }
  });

  app.get("/api/guides/:slug", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const guide = await storage.getUserGuideBySlug(req.params.slug);
      if (!guide) {
        return res.status(404).json({ error: "Guide not found" });
      }
      if (!guide.published) {
        return res.status(404).json({ error: "Guide not found" });
      }
      res.json(guide);
    } catch (error) {
      console.error("Error fetching guide:", error);
      res.status(500).json({ error: "Failed to fetch guide" });
    }
  });

  // Admin routes for managing guides
  app.get("/api/admin/guides", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const user = (req as any).user;
      if (!user?.isAdmin) {
        return res.status(403).json({ error: "Admin access required" });
      }
      const guides = await storage.getAllUserGuides();
      res.json(guides);
    } catch (error) {
      console.error("Error fetching admin guides:", error);
      res.status(500).json({ error: "Failed to fetch guides" });
    }
  });

  app.post("/api/admin/guides", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const user = (req as any).user;
      if (!user?.isAdmin) {
        return res.status(403).json({ error: "Admin access required" });
      }

      const { title, slug, content, sortOrder, published } = req.body;
      
      if (!title || !slug || !content) {
        return res.status(400).json({ error: "Title, slug, and content are required" });
      }

      // Check for duplicate slug
      const existing = await storage.getUserGuideBySlug(slug);
      if (existing) {
        return res.status(400).json({ error: "A guide with this slug already exists" });
      }

      const guide = await storage.createUserGuide({
        title,
        slug,
        content,
        sortOrder: sortOrder ?? 0,
        published: published ?? true,
      });
      res.status(201).json(guide);
    } catch (error) {
      console.error("Error creating guide:", error);
      res.status(500).json({ error: "Failed to create guide" });
    }
  });

  app.patch("/api/admin/guides/:id", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const user = (req as any).user;
      if (!user?.isAdmin) {
        return res.status(403).json({ error: "Admin access required" });
      }

      const guide = await storage.getUserGuide(req.params.id);
      if (!guide) {
        return res.status(404).json({ error: "Guide not found" });
      }

      const { title, slug, content, sortOrder, published } = req.body;
      
      // Check for duplicate slug (if changing)
      if (slug && slug !== guide.slug) {
        const existing = await storage.getUserGuideBySlug(slug);
        if (existing) {
          return res.status(400).json({ error: "A guide with this slug already exists" });
        }
      }

      const updated = await storage.updateUserGuide(req.params.id, {
        ...(title !== undefined && { title }),
        ...(slug !== undefined && { slug }),
        ...(content !== undefined && { content }),
        ...(sortOrder !== undefined && { sortOrder }),
        ...(published !== undefined && { published }),
      });
      res.json(updated);
    } catch (error) {
      console.error("Error updating guide:", error);
      res.status(500).json({ error: "Failed to update guide" });
    }
  });

  app.delete("/api/admin/guides/:id", isAuthenticated, async (req: Request, res: Response) => {
    try {
      const user = (req as any).user;
      if (!user?.isAdmin) {
        return res.status(403).json({ error: "Admin access required" });
      }

      const guide = await storage.getUserGuide(req.params.id);
      if (!guide) {
        return res.status(404).json({ error: "Guide not found" });
      }

      await storage.deleteUserGuide(req.params.id);
      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting guide:", error);
      res.status(500).json({ error: "Failed to delete guide" });
    }
  });

  return httpServer;
}

// Extract placeholders from HTML template
function extractPlaceholders(htmlContent: string): string[] {
  const regex = /\{\{(\w+)\}\}/g;
  const placeholders: Set<string> = new Set();
  let match;
  while ((match = regex.exec(htmlContent)) !== null) {
    placeholders.add(match[1]);
  }
  return Array.from(placeholders);
}

// Seed signature spots for the lease_v1 template
async function seedSignatureSpots() {
  const templateId = "lease_v1";

  // Check if spots already exist
  const existingSpots = await storage.getSignatureSpots(templateId);
  if (existingSpots.length > 0) {
    console.log("Signature spots already seeded");
    return;
  }

  console.log("Seeding signature spots for lease_v1...");

  // A4 dimensions: 595.28 x 841.89 points
  const spots = [
    {
      templateId,
      spotKey: "tenant_initial_p1",
      page: 1,
      x: 72, // left margin
      y: 680, // near bottom of page 1
      w: 80,
      h: 40,
      kind: "initial",
    },
    {
      templateId,
      spotKey: "tenant_initial_p2",
      page: 2,
      x: 72,
      y: 480,
      w: 80,
      h: 40,
      kind: "initial",
    },
    {
      templateId,
      spotKey: "tenant_signature",
      page: 2,
      x: 72,
      y: 620,
      w: 200,
      h: 60,
      kind: "signature",
    },
  ];

  for (const spot of spots) {
    await storage.createSignatureSpot(spot);
    console.log(`Created spot: ${spot.spotKey}`);
  }

  console.log("Signature spots seeded successfully");
}

