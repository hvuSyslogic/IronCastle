using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp.@operator.jcajce
{


	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using PublicKeyAlgorithmTags = org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;

	public class OperatorHelper
	{
		private JcaJceHelper helper;

		public OperatorHelper(JcaJceHelper helper)
		{
			this.helper = helper;
		}

		/// <summary>
		/// Return an appropriate name for the hash algorithm represented by the passed
		/// in hash algorithm ID number (JCA message digest naming convention).
		/// </summary>
		/// <param name="hashAlgorithm"> the algorithm ID for a hash algorithm. </param>
		/// <returns> a String representation of the hash name. </returns>
		public virtual string getDigestName(int hashAlgorithm)
		{
			switch (hashAlgorithm)
			{
			case HashAlgorithmTags_Fields.SHA1:
				return "SHA-1";
			case HashAlgorithmTags_Fields.MD2:
				return "MD2";
			case HashAlgorithmTags_Fields.MD5:
				return "MD5";
			case HashAlgorithmTags_Fields.RIPEMD160:
				return "RIPEMD160";
			case HashAlgorithmTags_Fields.SHA256:
				return "SHA-256";
			case HashAlgorithmTags_Fields.SHA384:
				return "SHA-384";
			case HashAlgorithmTags_Fields.SHA512:
				return "SHA-512";
			case HashAlgorithmTags_Fields.SHA224:
				return "SHA-224";
			case HashAlgorithmTags_Fields.TIGER_192:
				return "TIGER";
			default:
				throw new PGPException("unknown hash algorithm tag in getDigestName: " + hashAlgorithm);
			}
		}

		public virtual MessageDigest createDigest(int algorithm)
		{
			MessageDigest dig;

			string digestName = getDigestName(algorithm);
			try
			{
				dig = helper.createDigest(digestName);
			}
			catch (NoSuchAlgorithmException e)
			{
				if (algorithm >= HashAlgorithmTags_Fields.SHA256 && algorithm <= HashAlgorithmTags_Fields.SHA224)
				{
					dig = helper.createDigest("SHA" + digestName.Substring(4));
				}
				else
				{
					throw e;
				}
			}

			return dig;
		}

		public virtual KeyFactory createKeyFactory(string algorithm)
		{
			return helper.createKeyFactory(algorithm);
		}

		public virtual KeyAgreement createKeyAgreement(string algorithm)
		{
			return helper.createKeyAgreement(algorithm);
		}

		public virtual KeyPairGenerator createKeyPairGenerator(string algorithm)
		{
			return helper.createKeyPairGenerator(algorithm);
		}

		public virtual PGPDataDecryptor createDataDecryptor(bool withIntegrityPacket, int encAlgorithm, byte[] key)
		{
			try
			{
				SecretKey secretKey = new SecretKeySpec(key, PGPUtil.getSymmetricCipherName(encAlgorithm));

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final javax.crypto.Cipher c = createStreamCipher(encAlgorithm, withIntegrityPacket);
				Cipher c = createStreamCipher(encAlgorithm, withIntegrityPacket);

				if (withIntegrityPacket)
				{
					byte[] iv = new byte[c.getBlockSize()];

					c.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
				}
				else
				{
					c.init(Cipher.DECRYPT_MODE, secretKey);
				}

				return new PGPDataDecryptorAnonymousInnerClass(this, c);
			}
			catch (PGPException e)
			{
				throw e;
			}
			catch (Exception e)
			{
				throw new PGPException("Exception creating cipher", e);
			}
		}

		public class PGPDataDecryptorAnonymousInnerClass : PGPDataDecryptor
		{
			private readonly OperatorHelper outerInstance;

			private Cipher c;

			public PGPDataDecryptorAnonymousInnerClass(OperatorHelper outerInstance, Cipher c)
			{
				this.outerInstance = outerInstance;
				this.c = c;
			}

			public InputStream getInputStream(InputStream @in)
			{
				return new CipherInputStream(@in, c);
			}

			public int getBlockSize()
			{
				return c.getBlockSize();
			}

			public PGPDigestCalculator getIntegrityCalculator()
			{
				return new SHA1PGPDigestCalculator();
			}
		}

		public virtual Cipher createStreamCipher(int encAlgorithm, bool withIntegrityPacket)
		{
			string mode = (withIntegrityPacket) ? "CFB" : "OpenPGPCFB";

			string cName = PGPUtil.getSymmetricCipherName(encAlgorithm) + "/" + mode + "/NoPadding";

			return createCipher(cName);
		}

		public virtual Cipher createCipher(string cipherName)
		{
			try
			{
				return helper.createCipher(cipherName);
			}
			catch (GeneralSecurityException e)
			{
				throw new PGPException("cannot create cipher: " + e.Message, e);
			}
		}

		public virtual Cipher createPublicKeyCipher(int encAlgorithm)
		{
			switch (encAlgorithm)
			{
			case PGPPublicKey.RSA_ENCRYPT:
			case PGPPublicKey.RSA_GENERAL:
				return createCipher("RSA/ECB/PKCS1Padding");
			case PGPPublicKey.ELGAMAL_ENCRYPT:
			case PGPPublicKey.ELGAMAL_GENERAL:
				return createCipher("ElGamal/ECB/PKCS1Padding");
			case PGPPublicKey.DSA:
				throw new PGPException("Can't use DSA for encryption.");
			case PGPPublicKey.ECDSA:
				throw new PGPException("Can't use ECDSA for encryption.");
			default:
				throw new PGPException("unknown asymmetric algorithm: " + encAlgorithm);
			}
		}

		public virtual Cipher createKeyWrapper(int encAlgorithm)
		{
			try
			{
				switch (encAlgorithm)
				{
				case SymmetricKeyAlgorithmTags_Fields.AES_128:
				case SymmetricKeyAlgorithmTags_Fields.AES_192:
				case SymmetricKeyAlgorithmTags_Fields.AES_256:
					return helper.createCipher("AESWrap");
				case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_128:
				case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_192:
				case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_256:
					return helper.createCipher("CamelliaWrap");
				default:
					throw new PGPException("unknown wrap algorithm: " + encAlgorithm);
				}
			}
			catch (GeneralSecurityException e)
			{
				throw new PGPException("cannot create cipher: " + e.Message, e);
			}
		}

		private Signature createSignature(string cipherName)
		{
			try
			{
				return helper.createSignature(cipherName);
			}
			catch (GeneralSecurityException e)
			{
				throw new PGPException("cannot create signature: " + e.Message, e);
			}
		}

		public virtual Signature createSignature(int keyAlgorithm, int hashAlgorithm)
		{
			string encAlg;

			switch (keyAlgorithm)
			{
			case PublicKeyAlgorithmTags_Fields.RSA_GENERAL:
			case PublicKeyAlgorithmTags_Fields.RSA_SIGN:
				encAlg = "RSA";
				break;
			case PublicKeyAlgorithmTags_Fields.DSA:
				encAlg = "DSA";
				break;
			case PublicKeyAlgorithmTags_Fields.ELGAMAL_ENCRYPT: // in some malformed cases.
			case PublicKeyAlgorithmTags_Fields.ELGAMAL_GENERAL:
				encAlg = "ElGamal";
				break;
			case PublicKeyAlgorithmTags_Fields.ECDSA:
				encAlg = "ECDSA";
				break;
			default:
				throw new PGPException("unknown algorithm tag in signature:" + keyAlgorithm);
			}

			return createSignature(PGPUtil.getDigestName(hashAlgorithm) + "with" + encAlg);
		}

		public virtual AlgorithmParameters createAlgorithmParameters(string algorithm)
		{
			return helper.createAlgorithmParameters(algorithm);
		}
	}

}