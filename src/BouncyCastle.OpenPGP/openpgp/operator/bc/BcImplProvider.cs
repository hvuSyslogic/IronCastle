using org.bouncycastle.bcpg;

namespace org.bouncycastle.openpgp.@operator.bc
{
	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using PublicKeyAlgorithmTags = org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using AsymmetricBlockCipher = org.bouncycastle.crypto.AsymmetricBlockCipher;
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using Digest = org.bouncycastle.crypto.Digest;
	using Signer = org.bouncycastle.crypto.Signer;
	using Wrapper = org.bouncycastle.crypto.Wrapper;
	using MD2Digest = org.bouncycastle.crypto.digests.MD2Digest;
	using MD5Digest = org.bouncycastle.crypto.digests.MD5Digest;
	using RIPEMD160Digest = org.bouncycastle.crypto.digests.RIPEMD160Digest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using SHA224Digest = org.bouncycastle.crypto.digests.SHA224Digest;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using SHA384Digest = org.bouncycastle.crypto.digests.SHA384Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using TigerDigest = org.bouncycastle.crypto.digests.TigerDigest;
	using PKCS1Encoding = org.bouncycastle.crypto.encodings.PKCS1Encoding;
	using AESEngine = org.bouncycastle.crypto.engines.AESEngine;
	using BlowfishEngine = org.bouncycastle.crypto.engines.BlowfishEngine;
	using CAST5Engine = org.bouncycastle.crypto.engines.CAST5Engine;
	using CamelliaEngine = org.bouncycastle.crypto.engines.CamelliaEngine;
	using DESEngine = org.bouncycastle.crypto.engines.DESEngine;
	using DESedeEngine = org.bouncycastle.crypto.engines.DESedeEngine;
	using ElGamalEngine = org.bouncycastle.crypto.engines.ElGamalEngine;
	using IDEAEngine = org.bouncycastle.crypto.engines.IDEAEngine;
	using RFC3394WrapEngine = org.bouncycastle.crypto.engines.RFC3394WrapEngine;
	using RSABlindedEngine = org.bouncycastle.crypto.engines.RSABlindedEngine;
	using TwofishEngine = org.bouncycastle.crypto.engines.TwofishEngine;
	using DSADigestSigner = org.bouncycastle.crypto.signers.DSADigestSigner;
	using DSASigner = org.bouncycastle.crypto.signers.DSASigner;
	using ECDSASigner = org.bouncycastle.crypto.signers.ECDSASigner;
	using RSADigestSigner = org.bouncycastle.crypto.signers.RSADigestSigner;

	public class BcImplProvider
	{
		internal static Digest createDigest(int algorithm)
		{
			switch (algorithm)
			{
			case HashAlgorithmTags_Fields.SHA1:
				return new SHA1Digest();
			case HashAlgorithmTags_Fields.SHA224:
				return new SHA224Digest();
			case HashAlgorithmTags_Fields.SHA256:
				return new SHA256Digest();
			case HashAlgorithmTags_Fields.SHA384:
				return new SHA384Digest();
			case HashAlgorithmTags_Fields.SHA512:
				return new SHA512Digest();
			case HashAlgorithmTags_Fields.MD2:
				return new MD2Digest();
			case HashAlgorithmTags_Fields.MD5:
				return new MD5Digest();
			case HashAlgorithmTags_Fields.RIPEMD160:
				return new RIPEMD160Digest();
			case HashAlgorithmTags_Fields.TIGER_192:
				return new TigerDigest();
			default:
				throw new PGPException("cannot recognise digest");
			}
		}

		internal static Signer createSigner(int keyAlgorithm, int hashAlgorithm)
		{
			switch (keyAlgorithm)
			{
			case PublicKeyAlgorithmTags_Fields.RSA_GENERAL:
			case PublicKeyAlgorithmTags_Fields.RSA_SIGN:
				return new RSADigestSigner(createDigest(hashAlgorithm));
			case PublicKeyAlgorithmTags_Fields.DSA:
				return new DSADigestSigner(new DSASigner(), createDigest(hashAlgorithm));
			case PublicKeyAlgorithmTags_Fields.ECDSA:
				return new DSADigestSigner(new ECDSASigner(), createDigest(hashAlgorithm));
			default:
				throw new PGPException("cannot recognise keyAlgorithm: " + keyAlgorithm);
			}
		}

		internal static BlockCipher createBlockCipher(int encAlgorithm)
		{
			BlockCipher engine;

			switch (encAlgorithm)
			{
			case SymmetricKeyAlgorithmTags_Fields.AES_128:
			case SymmetricKeyAlgorithmTags_Fields.AES_192:
			case SymmetricKeyAlgorithmTags_Fields.AES_256:
				engine = new AESEngine();
				break;
			case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_128:
			case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_192:
			case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_256:
				engine = new CamelliaEngine();
				break;
			case SymmetricKeyAlgorithmTags_Fields.BLOWFISH:
				engine = new BlowfishEngine();
				break;
			case SymmetricKeyAlgorithmTags_Fields.CAST5:
				engine = new CAST5Engine();
				break;
			case SymmetricKeyAlgorithmTags_Fields.DES:
				engine = new DESEngine();
				break;
			case SymmetricKeyAlgorithmTags_Fields.IDEA:
				engine = new IDEAEngine();
				break;
			case SymmetricKeyAlgorithmTags_Fields.TWOFISH:
				engine = new TwofishEngine();
				break;
			case SymmetricKeyAlgorithmTags_Fields.TRIPLE_DES:
				engine = new DESedeEngine();
				break;
			default:
				throw new PGPException("cannot recognise cipher");
			}

			return engine;
		}

		internal static Wrapper createWrapper(int encAlgorithm)
		{
			switch (encAlgorithm)
			{
			case SymmetricKeyAlgorithmTags_Fields.AES_128:
			case SymmetricKeyAlgorithmTags_Fields.AES_192:
			case SymmetricKeyAlgorithmTags_Fields.AES_256:
				return new RFC3394WrapEngine(new AESEngine());
			case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_128:
			case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_192:
			case SymmetricKeyAlgorithmTags_Fields.CAMELLIA_256:
				return new RFC3394WrapEngine(new CamelliaEngine());
			default:
				throw new PGPException("unknown wrap algorithm: " + encAlgorithm);
			}
		}

		internal static AsymmetricBlockCipher createPublicKeyCipher(int encAlgorithm)
		{
			AsymmetricBlockCipher c;

			switch (encAlgorithm)
			{
			case PGPPublicKey.RSA_ENCRYPT:
			case PGPPublicKey.RSA_GENERAL:
				c = new PKCS1Encoding(new RSABlindedEngine());
				break;
			case PGPPublicKey.ELGAMAL_ENCRYPT:
			case PGPPublicKey.ELGAMAL_GENERAL:
				c = new PKCS1Encoding(new ElGamalEngine());
				break;
			case PGPPublicKey.DSA:
				throw new PGPException("Can't use DSA for encryption.");
			case PGPPublicKey.ECDSA:
				throw new PGPException("Can't use ECDSA for encryption.");
			case PGPPublicKey.ECDH:
				throw new PGPException("Not implemented.");
			default:
				throw new PGPException("unknown asymmetric algorithm: " + encAlgorithm);
			}

			return c;
		}
	}

}