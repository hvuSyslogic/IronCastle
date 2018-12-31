using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1;

using System;
using System.IO;
using org.bouncycastle.crypto.encodings;
using org.bouncycastle.crypto.engines;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.signers
{

														
	public class RSADigestSigner : Signer
	{
		private readonly AsymmetricBlockCipher rsaEngine = new PKCS1Encoding(new RSABlindedEngine());
		private readonly AlgorithmIdentifier algId;
		private readonly Digest digest;
		private bool forSigning;

		private static readonly Hashtable oidMap = new Hashtable();

		/*
		 * Load OID table.
		 */
		static RSADigestSigner()
		{
			oidMap.put("RIPEMD128", TeleTrusTObjectIdentifiers_Fields.ripemd128);
			oidMap.put("RIPEMD160", TeleTrusTObjectIdentifiers_Fields.ripemd160);
			oidMap.put("RIPEMD256", TeleTrusTObjectIdentifiers_Fields.ripemd256);

			oidMap.put("SHA-1", X509ObjectIdentifiers_Fields.id_SHA1);
			oidMap.put("SHA-224", NISTObjectIdentifiers_Fields.id_sha224);
			oidMap.put("SHA-256", NISTObjectIdentifiers_Fields.id_sha256);
			oidMap.put("SHA-384", NISTObjectIdentifiers_Fields.id_sha384);
			oidMap.put("SHA-512", NISTObjectIdentifiers_Fields.id_sha512);
			oidMap.put("SHA-512/224", NISTObjectIdentifiers_Fields.id_sha512_224);
			oidMap.put("SHA-512/256", NISTObjectIdentifiers_Fields.id_sha512_256);

			oidMap.put("SHA3-224", NISTObjectIdentifiers_Fields.id_sha3_224);
			oidMap.put("SHA3-256", NISTObjectIdentifiers_Fields.id_sha3_256);
			oidMap.put("SHA3-384", NISTObjectIdentifiers_Fields.id_sha3_384);
			oidMap.put("SHA3-512", NISTObjectIdentifiers_Fields.id_sha3_512);

			oidMap.put("MD2", PKCSObjectIdentifiers_Fields.md2);
			oidMap.put("MD4", PKCSObjectIdentifiers_Fields.md4);
			oidMap.put("MD5", PKCSObjectIdentifiers_Fields.md5);
		}

		public RSADigestSigner(Digest digest) : this(digest, (ASN1ObjectIdentifier)oidMap.get(digest.getAlgorithmName()))
		{
		}

		public RSADigestSigner(Digest digest, ASN1ObjectIdentifier digestOid)
		{
			this.digest = digest;
			this.algId = new AlgorithmIdentifier(digestOid, DERNull.INSTANCE);
		}

		/// <summary>
		/// @deprecated
		/// </summary>
		public virtual string getAlgorithmName()
		{
			return digest.getAlgorithmName() + "withRSA";
		}

		/// <summary>
		/// initialise the signer for signing or verification.
		/// </summary>
		/// <param name="forSigning">
		///            true if for signing, false otherwise </param>
		/// <param name="parameters">
		///            necessary parameters. </param>
		public virtual void init(bool forSigning, CipherParameters parameters)
		{
			this.forSigning = forSigning;
			AsymmetricKeyParameter k;

			if (parameters is ParametersWithRandom)
			{
				k = (AsymmetricKeyParameter)((ParametersWithRandom)parameters).getParameters();
			}
			else
			{
				k = (AsymmetricKeyParameter)parameters;
			}

			if (forSigning && !k.isPrivate())
			{
				throw new IllegalArgumentException("signing requires private key");
			}

			if (!forSigning && k.isPrivate())
			{
				throw new IllegalArgumentException("verification requires public key");
			}

			reset();

			rsaEngine.init(forSigning, parameters);
		}

		/// <summary>
		/// update the internal digest with the byte b
		/// </summary>
		public virtual void update(byte input)
		{
			digest.update(input);
		}

		/// <summary>
		/// update the internal digest with the byte array in
		/// </summary>
		public virtual void update(byte[] input, int inOff, int length)
		{
			digest.update(input, inOff, length);
		}

		/// <summary>
		/// Generate a signature for the message we've been loaded with using the key
		/// we were initialised with.
		/// </summary>
		public virtual byte[] generateSignature()
		{
			if (!forSigning)
			{
				throw new IllegalStateException("RSADigestSigner not initialised for signature generation.");
			}

			byte[] hash = new byte[digest.getDigestSize()];
			digest.doFinal(hash, 0);

			try
			{
				byte[] data = derEncode(hash);
				return rsaEngine.processBlock(data, 0, data.Length);
			}
			catch (IOException e)
			{
				throw new CryptoException("unable to encode signature: " + e.Message, e);
			}
		}

		/// <summary>
		/// return true if the internal state represents the signature described in
		/// the passed in array.
		/// </summary>
		public virtual bool verifySignature(byte[] signature)
		{
			if (forSigning)
			{
				throw new IllegalStateException("RSADigestSigner not initialised for verification");
			}

			byte[] hash = new byte[digest.getDigestSize()];

			digest.doFinal(hash, 0);

			byte[] sig;
			byte[] expected;

			try
			{
				sig = rsaEngine.processBlock(signature, 0, signature.Length);
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
				int sigOffset = sig.Length - hash.Length - 2;
				int expectedOffset = expected.Length - hash.Length - 2;

				expected[1] -= 2; // adjust lengths
				expected[3] -= 2;

				int nonEqual = 0;

				for (int i = 0; i < hash.Length; i++)
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

		public virtual void reset()
		{
			digest.reset();
		}

		private byte[] derEncode(byte[] hash)
		{
			DigestInfo dInfo = new DigestInfo(algId, hash);

			return dInfo.getEncoded(ASN1Encoding_Fields.DER);
		}
	}

}