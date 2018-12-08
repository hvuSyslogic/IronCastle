using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.rsa
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DigestInfo = org.bouncycastle.asn1.x509.DigestInfo;
	using AsymmetricBlockCipher = org.bouncycastle.crypto.AsymmetricBlockCipher;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using Digest = org.bouncycastle.crypto.Digest;
	using MD2Digest = org.bouncycastle.crypto.digests.MD2Digest;
	using MD4Digest = org.bouncycastle.crypto.digests.MD4Digest;
	using NullDigest = org.bouncycastle.crypto.digests.NullDigest;
	using RIPEMD128Digest = org.bouncycastle.crypto.digests.RIPEMD128Digest;
	using RIPEMD160Digest = org.bouncycastle.crypto.digests.RIPEMD160Digest;
	using RIPEMD256Digest = org.bouncycastle.crypto.digests.RIPEMD256Digest;
	using PKCS1Encoding = org.bouncycastle.crypto.encodings.PKCS1Encoding;
	using RSABlindedEngine = org.bouncycastle.crypto.engines.RSABlindedEngine;
	using DigestFactory = org.bouncycastle.crypto.util.DigestFactory;
	using Arrays = org.bouncycastle.util.Arrays;

	public class DigestSignatureSpi : SignatureSpi
	{
		private Digest digest;
		private AsymmetricBlockCipher cipher;
		private AlgorithmIdentifier algId;

		// care - this constructor is actually used by outside organisations
		public DigestSignatureSpi(Digest digest, AsymmetricBlockCipher cipher)
		{
			this.digest = digest;
			this.cipher = cipher;
			this.algId = null;
		}

		// care - this constructor is actually used by outside organisations
		public DigestSignatureSpi(ASN1ObjectIdentifier objId, Digest digest, AsymmetricBlockCipher cipher)
		{
			this.digest = digest;
			this.cipher = cipher;
			this.algId = new AlgorithmIdentifier(objId, DERNull.INSTANCE);
		}

		public virtual void engineInitVerify(PublicKey publicKey)
		{
			if (!(publicKey is RSAPublicKey))
			{
				throw new InvalidKeyException("Supplied key (" + getType(publicKey) + ") is not a RSAPublicKey instance");
			}

			CipherParameters param = RSAUtil.generatePublicKeyParameter((RSAPublicKey)publicKey);

			digest.reset();
			cipher.init(false, param);
		}

		public virtual void engineInitSign(PrivateKey privateKey)
		{
			if (!(privateKey is RSAPrivateKey))
			{
				throw new InvalidKeyException("Supplied key (" + getType(privateKey) + ") is not a RSAPrivateKey instance");
			}

			CipherParameters param = RSAUtil.generatePrivateKeyParameter((RSAPrivateKey)privateKey);

			digest.reset();

			cipher.init(true, param);
		}

		private string getType(object o)
		{
			if (o == null)
			{
				return null;
			}

			return o.GetType().getName();
		}

		public virtual void engineUpdate(byte b)
		{
			digest.update(b);
		}

		public virtual void engineUpdate(byte[] b, int off, int len)
		{
			digest.update(b, off, len);
		}

		public virtual byte[] engineSign()
		{
			byte[] hash = new byte[digest.getDigestSize()];

			digest.doFinal(hash, 0);

			try
			{
				byte[] bytes = derEncode(hash);

				return cipher.processBlock(bytes, 0, bytes.Length);
			}
			catch (ArrayIndexOutOfBoundsException)
			{
				throw new SignatureException("key too small for signature type");
			}
			catch (Exception e)
			{
				throw new SignatureException(e.ToString());
			}
		}

		public virtual bool engineVerify(byte[] sigBytes)
		{
			byte[] hash = new byte[digest.getDigestSize()];

			digest.doFinal(hash, 0);

			byte[] sig;
			byte[] expected;

			try
			{
				sig = cipher.processBlock(sigBytes, 0, sigBytes.Length);

				expected = derEncode(hash);
			}
			catch (Exception)
			{
				return false;
			}

			if (sig.Length == expected.Length)
			{
				return Arrays.constantTimeAreEqual(sig, expected);
			}
			else if (sig.Length == expected.Length - 2) // NULL left out
			{
				expected[1] -= 2; // adjust lengths
				expected[3] -= 2;

				int sigOffset = 4 + expected[3];
				int expectedOffset = sigOffset + 2;
				int nonEqual = 0;

				for (int i = 0; i < expected.Length - expectedOffset; i++)
				{
					nonEqual |= (sig[sigOffset + i] ^ expected[expectedOffset + i]);
				}

				for (int i = 0; i < sigOffset; i++)
				{
					nonEqual |= (sig[i] ^ expected[i]); // check header less NULL
				}

				return nonEqual == 0;
			}
			else
			{
				Arrays.constantTimeAreEqual(expected, expected); // keep time "steady".

				return false;
			}
		}

		public virtual void engineSetParameter(AlgorithmParameterSpec @params)
		{
			throw new UnsupportedOperationException("engineSetParameter unsupported");
		}

		/// @deprecated replaced with #engineSetParameter(java.security.spec.AlgorithmParameterSpec) 
		public virtual void engineSetParameter(string param, object value)
		{
			throw new UnsupportedOperationException("engineSetParameter unsupported");
		}

		/// <summary>
		/// @deprecated
		/// </summary>
		public virtual object engineGetParameter(string param)
		{
			return null;
		}

		public virtual AlgorithmParameters engineGetParameters()
		{
			return null;
		}

		private byte[] derEncode(byte[] hash)
		{
			if (algId == null)
			{
				// For raw RSA, the DigestInfo must be prepared externally
				return hash;
			}

			DigestInfo dInfo = new DigestInfo(algId, hash);

			return dInfo.getEncoded(ASN1Encoding_Fields.DER);
		}

		public class SHA1 : DigestSignatureSpi
		{
			public SHA1() : base(org.bouncycastle.asn1.oiw.OIWObjectIdentifiers_Fields.idSHA1, DigestFactory.createSHA1(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class SHA224 : DigestSignatureSpi
		{
			public SHA224() : base(org.bouncycastle.asn1.nist.NISTObjectIdentifiers_Fields.id_sha224, DigestFactory.createSHA224(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class SHA256 : DigestSignatureSpi
		{
			public SHA256() : base(org.bouncycastle.asn1.nist.NISTObjectIdentifiers_Fields.id_sha256, DigestFactory.createSHA256(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class SHA384 : DigestSignatureSpi
		{
			public SHA384() : base(org.bouncycastle.asn1.nist.NISTObjectIdentifiers_Fields.id_sha384, DigestFactory.createSHA384(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class SHA512 : DigestSignatureSpi
		{
			public SHA512() : base(org.bouncycastle.asn1.nist.NISTObjectIdentifiers_Fields.id_sha512, DigestFactory.createSHA512(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class SHA512_224 : DigestSignatureSpi
		{
			public SHA512_224() : base(org.bouncycastle.asn1.nist.NISTObjectIdentifiers_Fields.id_sha512_224, DigestFactory.createSHA512_224(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class SHA512_256 : DigestSignatureSpi
		{
			public SHA512_256() : base(org.bouncycastle.asn1.nist.NISTObjectIdentifiers_Fields.id_sha512_256, DigestFactory.createSHA512_256(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class SHA3_224 : DigestSignatureSpi
		{
			public SHA3_224() : base(org.bouncycastle.asn1.nist.NISTObjectIdentifiers_Fields.id_sha3_224, DigestFactory.createSHA3_224(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class SHA3_256 : DigestSignatureSpi
		{
			public SHA3_256() : base(org.bouncycastle.asn1.nist.NISTObjectIdentifiers_Fields.id_sha3_256, DigestFactory.createSHA3_256(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class SHA3_384 : DigestSignatureSpi
		{
			public SHA3_384() : base(org.bouncycastle.asn1.nist.NISTObjectIdentifiers_Fields.id_sha3_384, DigestFactory.createSHA3_384(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class SHA3_512 : DigestSignatureSpi
		{
			public SHA3_512() : base(org.bouncycastle.asn1.nist.NISTObjectIdentifiers_Fields.id_sha3_512, DigestFactory.createSHA3_512(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class MD2 : DigestSignatureSpi
		{
			public MD2() : base(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.md2, new MD2Digest(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class MD4 : DigestSignatureSpi
		{
			public MD4() : base(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.md4, new MD4Digest(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class MD5 : DigestSignatureSpi
		{
			public MD5() : base(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers_Fields.md5, DigestFactory.createMD5(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class RIPEMD160 : DigestSignatureSpi
		{
			public RIPEMD160() : base(org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers_Fields.ripemd160, new RIPEMD160Digest(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class RIPEMD128 : DigestSignatureSpi
		{
			public RIPEMD128() : base(org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers_Fields.ripemd128, new RIPEMD128Digest(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class RIPEMD256 : DigestSignatureSpi
		{
			public RIPEMD256() : base(org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers_Fields.ripemd256, new RIPEMD256Digest(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}

		public class noneRSA : DigestSignatureSpi
		{
			public noneRSA() : base(new NullDigest(), new PKCS1Encoding(new RSABlindedEngine()))
			{
			}
		}
	}

}