import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { SignupDto } from './dtos/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import mongoose, { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dtos/login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { v4 as uuidv4 } from 'uuid';
import { nanoid } from 'nanoid';
import { ResetToken } from './schemas/reset-token.schema';
import { MailService } from 'src/services/mail.service';
import { RolesService } from 'src/roles/roles.service';
import * as crypto from 'crypto';
import { UpdateProfileDto } from './dtos/update-profil.dto';
import * as admin from 'firebase-admin';
import { ConfigService } from '@nestjs/config';
import * as path from 'path';
import * as fs from 'fs';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectModel(User.name) private UserModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private RefreshTokenModel: Model<RefreshToken>,
    @InjectModel(ResetToken.name)
    private ResetTokenModel: Model<ResetToken>,
    private jwtService: JwtService,
    private mailService: MailService,
    private rolesService: RolesService,
    private configService: ConfigService,
  ) {}

  async signup(signupData: SignupDto, profilePicturePath?: string) {
    const { email, password, name } = signupData;

    // Check if email is already in use
    const emailInUse = await this.UserModel.findOne({ email });
    if (emailInUse) {
      throw new BadRequestException('Email already in use');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user document with optional profile picture
    const user = new this.UserModel({
      name,
      email,
      password: hashedPassword,
      profilePicture: profilePicturePath || null, // Use the provided path or set to null
    });

    await user.save();

    return {
      message: 'User created successfully',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        profilePicture: user.profilePicture,
      },
    };
  }

  async getUserProfile(userId: string) {
    const user = await this.UserModel.findById(userId).select('-password');
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return {
      name: user.name,
      email: user.email,
      profilePictureUrl: user.profilePicture
        ? `${process.env.API_URL}/${user.profilePicture}`
        : null,
    };
  }

  async login(credentials: LoginDto) {
    const { email, password } = credentials;
    //Find if user exists by email
    const user = await this.UserModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('Wrong credentials');
    }

    //Compare entered password with existing password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong credentials');
    }

    //Generate JWT tokens
    const tokens = await this.generateUserTokens(user._id);
    return {
      ...tokens,
      userId: user._id,
    };
  }
  async refreshTokens(refreshToken: string) {
    const token = await this.RefreshTokenModel.findOne({
      token: refreshToken,
      expiryDate: { $gte: new Date() },
    });

    if (!token) {
      throw new UnauthorizedException('Refresh Token is invalid');
    }
    return this.generateUserTokens(token.userId);
  }

  async generateUserTokens(userId) {
    const accessToken = this.jwtService.sign({ userId }, { expiresIn: '10h' });
    const refreshToken = uuidv4();

    await this.storeRefreshToken(refreshToken, userId);
    return {
      accessToken,
      refreshToken,
    };
  }

  async storeRefreshToken(token: string, userId: string) {
    // Calculate expiry date 3 days from now
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);

    await this.RefreshTokenModel.updateOne(
      { userId },
      { $set: { expiryDate, token } },
      {
        upsert: true,
      },
    );
  }

  async changePassword(userId, oldPassword: string, newPassword: string) {
    //Find the user
    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found...');
    }

    //Compare the old password with the password in DB
    const passwordMatch = await bcrypt.compare(oldPassword, user.password);
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong credentials');
    }

    //Change user's password
    const newHashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = newHashedPassword;
    await user.save();
  }

  async forgotPassword(email: string) {
    // Vérifier si l'utilisateur existe
    const user = await this.UserModel.findOne({ email });

    if (user) {
      // Si l'utilisateur existe, générer un mot de passe temporaire
      const newPassword = this.generateRandomPassword(12);
      user.password = await bcrypt.hash(newPassword, 12);
      await user.save();

      // Envoyer le nouveau mot de passe par email
      await this.mailService.sendPasswordResetEmail(email, newPassword);
    }

    return {
      message:
        'Si cet utilisateur existe, il recevra un nouvel email avec son mot de passe.',
    };
  }

  private generateRandomPassword(length = 12): string {
    const charset =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
    let password = '';
    const randomBytes = crypto.randomBytes(length);

    for (let i = 0; i < length; i++) {
      password += charset[randomBytes[i] % charset.length];
    }

    // Limiter la longueur du mot de passe généré
    return password.slice(0, length);
  }

  async resetPassword(resetToken: string) {
    this.logger.debug('Reset password function called');

    try {
      const token = await this.ResetTokenModel.findOneAndDelete({
        token: resetToken,
        expiryDate: { $gte: new Date() },
      });

      if (!token) {
        this.logger.warn(`Invalid or expired reset token: ${resetToken}`);
        throw new UnauthorizedException('Invalid or expired reset link');
      }

      const user = await this.UserModel.findById(token.userId);
      if (!user) {
        this.logger.error(`User not found for token: ${resetToken}`);
        throw new InternalServerErrorException('User not found');
      }

      const newPassword = this.generateRandomPassword(12);
      this.logger.debug(`Generated new password for user: ${user.email}`);

      user.password = await bcrypt.hash(newPassword, 12);
      await user.save();
      this.logger.debug(`New password saved for user: ${user.email}`);

      await this.mailService.sendPasswordResetEmail(user.email, newPassword);
      this.logger.debug(`Password reset email sent to: ${user.email}`);

      return { message: 'A new password has been sent to your email address.' };
    } catch (error) {
      this.logger.error(
        `Error in resetPassword: ${error.message}`,
        error.stack,
      );
      throw error;
    }
  }

  async getUserPermissions(userId: string) {
    const user = await this.UserModel.findById(userId);

    if (!user) throw new BadRequestException();

    const role = await this.rolesService.getRoleById(user.roleId.toString());
    return role.permissions;
  }


  private getUploadPath(): string {
    return path.join(process.cwd(), 'uploads');
  }


  async updateProfile(
    userId: string,
    updateProfileDto: UpdateProfileDto,
    file?: Express.Multer.File,
  ) {
    const user = await this.UserModel.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }
  
    if (updateProfileDto.name) {
      user.name = updateProfileDto.name;
    }
  
    if (updateProfileDto.oldPassword && updateProfileDto.newPassword) {
      const isPasswordValid = await bcrypt.compare(
        updateProfileDto.oldPassword,
        user.password,
      );
      if (!isPasswordValid) {
        throw new BadRequestException('Old password is incorrect');
      }
      user.password = await bcrypt.hash(updateProfileDto.newPassword, 10);
    }
  
    if (file) {
      try {
        // Get the correct upload path using getUploadPath
        const uploadPath = this.getUploadPath();
  
        // Delete the old profile picture if it exists
        if (user.profilePicture) {
          // Remove the 'uploads/' prefix from the stored path to avoid double 'uploads' in the path
          const oldPicturePath = path.join(uploadPath, user.profilePicture.replace('uploads/', ''));
          console.log('Attempting to delete old profile picture at:', oldPicturePath);
  
          if (fs.existsSync(oldPicturePath)) {
            fs.unlinkSync(oldPicturePath); // Delete the old profile picture
          } else {
            console.log('Old profile picture not found, skipping deletion');
          }
        }
  
        // Save the new profile picture path
        user.profilePicture = `uploads/${file.filename}`;
      } catch (error) {
        console.error('Error handling profile picture:', error);
        throw new BadRequestException('Error processing profile picture');
      }
    }
  
    await user.save();
  
    return {
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        profilePicture: user.profilePicture,
      },
    };
  }


  async googleLogin(idToken: string) {
    try {
      console.log('ID Token Received: ', idToken); // Add this line to log the token
      const decodedToken = await admin.auth().verifyIdToken(idToken);
      const { email, name, picture } = decodedToken;

      let user = await this.UserModel.findOne({ email });

      if (!user) {
        user = new this.UserModel({
          email,
          name,
          profilePicture: picture,
          password: await bcrypt.hash(nanoid(), 10),
        });
        await user.save();
      }

      const tokens = await this.generateUserTokens(user._id);

      return {
        ...tokens,
        userId: user._id,
        name: user.name,
        email: user.email,
        profilePicture: user.profilePicture,
      };
    } catch (error) {
      this.logger.error(`Google Login Error: ${error.message}`, error.stack);
      if (error.code === 'auth/id-token-expired') {
        throw new UnauthorizedException('Google token has expired');
      } else if (error.code === 'auth/invalid-id-token') {
        throw new UnauthorizedException('Invalid Google token');
      } else {
        throw new InternalServerErrorException(
          `An error occurred during Google login: ${error.message}`,
        );
      }
    }
  }
}
