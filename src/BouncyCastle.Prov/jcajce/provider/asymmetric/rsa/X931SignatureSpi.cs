using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.rsa
{

	using AsymmetricBlockCipher = org.bouncycastle.crypto.AsymmetricBlockCipher;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using Digest = org.bouncycastle.crypto.Digest;
	using RIPEMD128Digest = org.bouncycastle.crypto.digests.RIPEMD128Digest;
	using RIPEMD160Digest = org.bouncycastle.crypto.digests.RIPEMD160Digest;
	using WhirlpoolDigest = org.bouncycastle.crypto.digests.WhirlpoolDigest;
	using RSABlindedEngine = org.bouncycastle.crypto.engines.RSABlindedEngine;
	using X931Signer = org.bouncycastle.crypto.signers.X931Signer;
	using DigestFactory = org.bouncycastle.crypto.util.DigestFactory;

	public class X931SignatureSpi : SignatureSpi
	{
		private X931Signer signer;

		public X931SignatureSpi(Digest digest, AsymmetricBlockCipher cipher)
		{
			signer = new X931Signer(cipher, digest);
		}

		public virtual void engineInitVerify(PublicKey publicKey)
		{
			CipherParameters param = RSAUtil.generatePublicKeyParameter((RSAPublicKey)publicKey);

			signer.init(false, param);
		}

		public virtual void engineInitSign(PrivateKey privateKey)
		{
			CipherParameters param = RSAUtil.generatePrivateKeyParameter((RSAPrivateKey)privateKey);

			signer.init(true, param);
		}

		public virtual void engineUpdate(byte b)
		{
			signer.update(b);
		}

		public virtual void engineUpdate(byte[] b, int off, int len)
		{
			signer.update(b, off, len);
		}

		public virtual byte[] engineSign()
		{
			try
			{
				byte[] sig = signer.generateSignature();

				return sig;
			}
			catch (Exception e)
			{
				throw new SignatureException(e.ToString());
			}
		}

		public virtual bool engineVerify(byte[] sigBytes)
		{
			bool yes = signer.verifySignature(sigBytes);

			return yes;
		}

		public virtual void engineSetParameter(AlgorithmParameterSpec @params)
		{
			throw new UnsupportedOperationException("engineSetParameter unsupported");
		}

		/// @deprecated replaced with <a href="#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">engineSetParameter(java.security.spec.AlgorithmParameterSpec)</a> 
		public virtual void engineSetParameter(string param, object value)
		{
			throw new UnsupportedOperationException("engineSetParameter unsupported");
		}

		/// <summary>
		/// @deprecated
		/// </summary>
		public virtual object engineGetParameter(string param)
		{
			throw new UnsupportedOperationException("engineSetParameter unsupported");
		}

		public class RIPEMD128WithRSAEncryption : X931SignatureSpi
		{
			public RIPEMD128WithRSAEncryption() : base(new RIPEMD128Digest(), new RSABlindedEngine())
			{
			}
		}

		public class RIPEMD160WithRSAEncryption : X931SignatureSpi
		{
			public RIPEMD160WithRSAEncryption() : base(new RIPEMD160Digest(), new RSABlindedEngine())
			{
			}
		}

		public class SHA1WithRSAEncryption : X931SignatureSpi
		{
			public SHA1WithRSAEncryption() : base(DigestFactory.createSHA1(), new RSABlindedEngine())
			{
			}
		}

		public class SHA224WithRSAEncryption : X931SignatureSpi
		{
			public SHA224WithRSAEncryption() : base(DigestFactory.createSHA224(), new RSABlindedEngine())
			{
			}
		}

		public class SHA256WithRSAEncryption : X931SignatureSpi
		{
			public SHA256WithRSAEncryption() : base(DigestFactory.createSHA256(), new RSABlindedEngine())
			{
			}
		}

		public class SHA384WithRSAEncryption : X931SignatureSpi
		{
			public SHA384WithRSAEncryption() : base(DigestFactory.createSHA384(), new RSABlindedEngine())
			{
			}
		}

		public class SHA512WithRSAEncryption : X931SignatureSpi
		{
			public SHA512WithRSAEncryption() : base(DigestFactory.createSHA512(), new RSABlindedEngine())
			{
			}
		}

		public class SHA512_224WithRSAEncryption : X931SignatureSpi
		{
			public SHA512_224WithRSAEncryption() : base(DigestFactory.createSHA512_224(), new RSABlindedEngine())
			{
			}
		}

		public class SHA512_256WithRSAEncryption : X931SignatureSpi
		{
			public SHA512_256WithRSAEncryption() : base(DigestFactory.createSHA512_256(), new RSABlindedEngine())
			{
			}
		}

		public class WhirlpoolWithRSAEncryption : X931SignatureSpi
		{
			public WhirlpoolWithRSAEncryption() : base(new WhirlpoolDigest(), new RSABlindedEngine())
			{
			}
		}
	}

}