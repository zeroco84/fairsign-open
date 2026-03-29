import type { Express } from "express";
import { authStorage } from "./storage";
import { isAuthenticated } from "./replitAuth";
import { authenticator } from "otplib";
import QRCode from "qrcode";
import multer from "multer";
import { nanoid } from "nanoid";
import { getStorageBackend } from "../../services/storageBackend";

const isAdmin = async (req: any, res: any, next: any) => {
  if (!req.user?.isAdmin) {
    return res.status(403).json({ message: "Admin access required" });
  }
  next();
};

export function registerAuthRoutes(app: Express): void {
  app.get("/api/auth/user", isAuthenticated, async (req: any, res) => {
    try {
      const user = req.user;
      res.json({
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        profileImageKey: user.profileImageKey,
        isAdmin: user.isAdmin,
        twoFactorEnabled: user.twoFactorEnabled,
        accountType: user.accountType || "free",
      });
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });

  // User: Update own profile (name)
  app.patch("/api/auth/profile", isAuthenticated, async (req: any, res) => {
    try {
      const { firstName, lastName } = req.body;
      
      if (firstName === undefined && lastName === undefined) {
        return res.status(400).json({ message: "At least one field is required" });
      }

      const user = await authStorage.updateProfile(
        req.user.id,
        firstName ?? req.user.firstName ?? "",
        lastName ?? req.user.lastName ?? ""
      );
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json({
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        profileImageKey: user.profileImageKey,
        isAdmin: user.isAdmin,
        twoFactorEnabled: user.twoFactorEnabled,
      });
    } catch (error) {
      console.error("Error updating profile:", error);
      res.status(500).json({ message: "Failed to update profile" });
    }
  });

  // User: Upload profile image
  const profileImageUpload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
    fileFilter: (req, file, cb) => {
      if (file.mimetype.startsWith('image/')) {
        cb(null, true);
      } else {
        cb(new Error('Only image files are allowed'));
      }
    }
  });

  app.post("/api/auth/profile/image", isAuthenticated, profileImageUpload.single('image'), async (req: any, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No image file provided" });
      }

      const storageBackend = getStorageBackend();
      let fileExtension = req.file.originalname.split('.').pop()?.toLowerCase() || 'jpg';
      if (!['jpg', 'jpeg', 'png', 'webp', 'gif'].includes(fileExtension)) {
        fileExtension = 'jpg';
      }
      const imageKey = `profiles/${req.user.id}/${nanoid()}.${fileExtension}`;
      
      let safeMimeType = req.file.mimetype;
      if (!['image/jpeg', 'image/png', 'image/webp', 'image/gif'].includes(safeMimeType)) {
        safeMimeType = 'image/jpeg';
      }

      await storageBackend.uploadBuffer(req.file.buffer, imageKey, safeMimeType);
      
      const user = await authStorage.updateProfileImage(req.user.id, imageKey);
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json({
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        profileImageKey: user.profileImageKey,
        isAdmin: user.isAdmin,
        twoFactorEnabled: user.twoFactorEnabled,
      });
    } catch (error) {
      console.error("Error uploading profile image:", error);
      res.status(500).json({ message: "Failed to upload profile image" });
    }
  });

  // User: Delete profile image
  app.delete("/api/auth/profile/image", isAuthenticated, async (req: any, res) => {
    try {
      const currentUser = await authStorage.getUser(req.user.id);
      
      // Note: Old profile images are not deleted to avoid complexity
      // They will be orphaned but can be cleaned up later if needed

      const user = await authStorage.updateProfileImage(req.user.id, null);
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json({
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        profileImageKey: user.profileImageKey,
        isAdmin: user.isAdmin,
        twoFactorEnabled: user.twoFactorEnabled,
      });
    } catch (error) {
      console.error("Error deleting profile image:", error);
      res.status(500).json({ message: "Failed to delete profile image" });
    }
  });

  // User: Get profile image URL
  app.get("/api/auth/profile/image-url", isAuthenticated, async (req: any, res) => {
    try {
      const user = await authStorage.getUser(req.user.id);
      
      if (!user?.profileImageKey) {
        return res.status(404).json({ message: "No profile image" });
      }

      const storageBackend = getStorageBackend();
      const url = await storageBackend.getSignedDownloadUrl(user.profileImageKey, 3600);
      
      res.json({ url });
    } catch (error) {
      console.error("Error getting profile image URL:", error);
      res.status(500).json({ message: "Failed to get profile image URL" });
    }
  });

  // Admin: Get all active users (non-deleted)
  app.get("/api/admin/users", isAuthenticated, isAdmin, async (req: any, res) => {
    try {
      const users = await authStorage.getAllUsers();
      const activeUsers = users.filter(u => !u.deletedAt);
      res.json(activeUsers.map(u => ({
        id: u.id,
        email: u.email,
        firstName: u.firstName,
        lastName: u.lastName,
        isAdmin: u.isAdmin,
        twoFactorEnabled: u.twoFactorEnabled,
        emailVerified: u.emailVerified ?? false,
        createdAt: u.createdAt,
        deletedAt: u.deletedAt,
        scheduledDeletionDate: u.scheduledDeletionDate,
        deletionReason: u.deletionReason,
        accountType: u.accountType ?? "free",
        subscriptionStatus: u.subscriptionStatus,
        isBlocked: u.isBlocked ?? false,
      })));
    } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).json({ message: "Failed to fetch users" });
    }
  });

  // Admin: Create new user
  app.post("/api/admin/users", isAuthenticated, isAdmin, async (req: any, res) => {
    try {
      const { email, password, firstName, lastName, isAdmin: userIsAdmin } = req.body;
      
      if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required" });
      }

      if (password.length < 8) {
        return res.status(400).json({ message: "Password must be at least 8 characters" });
      }

      const existing = await authStorage.getUserByEmail(email);
      if (existing) {
        return res.status(409).json({ message: "User with this email already exists" });
      }

      const user = await authStorage.createUser(email, password, firstName, lastName, userIsAdmin || false);
      res.status(201).json({
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isAdmin: user.isAdmin,
        twoFactorEnabled: user.twoFactorEnabled,
      });
    } catch (error) {
      console.error("Error creating user:", error);
      res.status(500).json({ message: "Failed to create user" });
    }
  });

  // Admin: Reset user password
  app.post("/api/admin/users/:id/reset-password", isAuthenticated, isAdmin, async (req: any, res) => {
    try {
      const { id } = req.params;
      const { newPassword } = req.body;
      
      if (!newPassword || newPassword.length < 8) {
        return res.status(400).json({ message: "Password must be at least 8 characters" });
      }

      const user = await authStorage.getUser(id);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      await authStorage.updatePassword(id, newPassword);
      res.json({ message: "Password reset successfully" });
    } catch (error) {
      console.error("Error resetting password:", error);
      res.status(500).json({ message: "Failed to reset password" });
    }
  });

  // Admin: Toggle 2FA for a user (disable only)
  app.post("/api/admin/users/:id/toggle-2fa", isAuthenticated, isAdmin, async (req: any, res) => {
    try {
      const { id } = req.params;
      const { enabled } = req.body;

      const user = await authStorage.getUser(id);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      if (enabled === false) {
        await authStorage.enableTwoFactor(id, false);
        res.json({ message: "2FA disabled", twoFactorEnabled: false });
      } else {
        return res.status(400).json({ message: "Users must enable 2FA themselves" });
      }
    } catch (error) {
      console.error("Error toggling 2FA:", error);
      res.status(500).json({ message: "Failed to toggle 2FA" });
    }
  });

  // Admin: Delete user
  app.delete("/api/admin/users/:id", isAuthenticated, isAdmin, async (req: any, res) => {
    try {
      const { id } = req.params;

      if (id === req.user.id) {
        return res.status(400).json({ message: "Cannot delete your own account" });
      }

      const user = await authStorage.getUser(id);
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      await authStorage.deleteUser(id);
      res.json({ message: "User deleted successfully" });
    } catch (error) {
      console.error("Error deleting user:", error);
      res.status(500).json({ message: "Failed to delete user" });
    }
  });

  // User: Setup 2FA (generate secret and QR code)
  app.post("/api/auth/2fa/setup", isAuthenticated, async (req: any, res) => {
    try {
      const user = req.user;
      
      if (user.twoFactorEnabled) {
        return res.status(400).json({ message: "2FA is already enabled" });
      }

      const secret = authenticator.generateSecret();
      await authStorage.setTwoFactorSecret(user.id, secret);

      const otpAuthUrl = authenticator.keyuri(user.email, "FairSign", secret);
      const qrCodeDataUrl = await QRCode.toDataURL(otpAuthUrl);

      res.json({
        secret,
        qrCode: qrCodeDataUrl,
      });
    } catch (error) {
      console.error("Error setting up 2FA:", error);
      res.status(500).json({ message: "Failed to setup 2FA" });
    }
  });

  // User: Verify and enable 2FA
  app.post("/api/auth/2fa/verify", isAuthenticated, async (req: any, res) => {
    try {
      const { code } = req.body;
      const user = await authStorage.getUser(req.user.id);

      if (!user || !user.twoFactorSecret) {
        return res.status(400).json({ message: "2FA setup not initiated" });
      }

      const isValid = authenticator.verify({ token: code, secret: user.twoFactorSecret });
      if (!isValid) {
        return res.status(401).json({ message: "Invalid verification code" });
      }

      await authStorage.enableTwoFactor(user.id, true);
      res.json({ message: "2FA enabled successfully", twoFactorEnabled: true });
    } catch (error) {
      console.error("Error verifying 2FA:", error);
      res.status(500).json({ message: "Failed to verify 2FA" });
    }
  });

  // User: Disable own 2FA
  app.post("/api/auth/2fa/disable", isAuthenticated, async (req: any, res) => {
    try {
      const { code } = req.body;
      const user = await authStorage.getUser(req.user.id);

      if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
        return res.status(400).json({ message: "2FA is not enabled" });
      }

      const isValid = authenticator.verify({ token: code, secret: user.twoFactorSecret });
      if (!isValid) {
        return res.status(401).json({ message: "Invalid verification code" });
      }

      await authStorage.enableTwoFactor(user.id, false);
      res.json({ message: "2FA disabled successfully", twoFactorEnabled: false });
    } catch (error) {
      console.error("Error disabling 2FA:", error);
      res.status(500).json({ message: "Failed to disable 2FA" });
    }
  });

  // Admin: Get storage settings
  app.get("/api/admin/storage-settings", isAuthenticated, isAdmin, async (req, res) => {
    try {
      const settings = await authStorage.getStorageSettings();
      res.json(settings);
    } catch (error) {
      console.error("Error fetching storage settings:", error);
      res.status(500).json({ message: "Failed to fetch storage settings" });
    }
  });

  // Admin: Update storage settings
  app.post("/api/admin/storage-settings", isAuthenticated, isAdmin, async (req, res) => {
    try {
      const { endpoint, bucket, region, accessKeyId, secretAccessKey, prefix } = req.body;

      if (!endpoint || !bucket) {
        return res.status(400).json({ message: "Endpoint and bucket are required" });
      }

      await authStorage.saveStorageSettings({
        endpoint,
        bucket,
        region: region || "auto",
        accessKeyId: accessKeyId || "",
        secretAccessKey: secretAccessKey || "",
        prefix: prefix || "",
      });

      res.json({ message: "Storage settings saved successfully" });
    } catch (error) {
      console.error("Error saving storage settings:", error);
      res.status(500).json({ message: "Failed to save storage settings" });
    }
  });

  // Admin: Test storage connection
  app.post("/api/admin/storage-settings/test", isAuthenticated, isAdmin, async (req, res) => {
    try {
      const { endpoint, bucket, region, accessKeyId, secretAccessKey } = req.body;

      if (!endpoint || !bucket || !accessKeyId) {
        return res.status(400).json({ 
          success: false, 
          message: "Endpoint, bucket, and access key ID are required" 
        });
      }

      let actualSecret = secretAccessKey;
      if (!secretAccessKey || secretAccessKey.startsWith("••••")) {
        actualSecret = await authStorage.getRawSecretAccessKey();
      }

      if (!actualSecret) {
        return res.status(400).json({
          success: false,
          message: "Secret access key is required"
        });
      }

      const { S3Client, ListObjectsV2Command } = await import("@aws-sdk/client-s3");
      const testClient = new S3Client({
        endpoint,
        region: region || "auto",
        credentials: {
          accessKeyId,
          secretAccessKey: actualSecret,
        },
        forcePathStyle: true,
      });

      await testClient.send(new ListObjectsV2Command({ Bucket: bucket, MaxKeys: 1 }));
      res.json({ success: true, message: "Connection successful" });
    } catch (error: any) {
      console.error("Storage connection test failed:", error);
      res.json({ success: false, message: error.message || "Connection failed" });
    }
  });
}
