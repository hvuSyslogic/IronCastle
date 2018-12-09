﻿using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.mceliece
{

	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using Digest = org.bouncycastle.crypto.Digest;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using DigestRandomGenerator = org.bouncycastle.crypto.prng.DigestRandomGenerator;
	using ByteUtils = org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
	using GF2Vector = org.bouncycastle.pqc.math.linearalgebra.GF2Vector;

	/// <summary>
	/// This class implements the Pointcheval conversion of the McEliecePKCS.
	/// Pointcheval presents a generic technique to make a CCA2-secure cryptosystem
	/// from any partially trapdoor one-way function in the random oracle model. For
	/// details, see D. Engelbert, R. Overbeck, A. Schmidt, "A summary of the
	/// development of the McEliece Cryptosystem", technical report.
	/// </summary>
	public class McEliecePointchevalCipher : MessageEncryptor
	{


		/// <summary>
		/// The OID of the algorithm.
		/// </summary>
		public const string OID = "1.3.6.1.4.1.8301.3.1.3.4.2.2";

		private Digest messDigest;

		private SecureRandom sr;

		/// <summary>
		/// The McEliece main parameters
		/// </summary>
		private int n, k, t;

		internal McElieceCCA2KeyParameters key;
		private bool forEncryption;

		public virtual void init(bool forEncryption, CipherParameters param)
		{
			this.forEncryption = forEncryption;

			if (forEncryption)
			{
				if (param is ParametersWithRandom)
				{
					ParametersWithRandom rParam = (ParametersWithRandom)param;

					this.sr = rParam.getRandom();
					this.key = (McElieceCCA2PublicKeyParameters)rParam.getParameters();
					this.initCipherEncrypt((McElieceCCA2PublicKeyParameters)key);

				}
				else
				{
					this.sr = CryptoServicesRegistrar.getSecureRandom();
					this.key = (McElieceCCA2PublicKeyParameters)param;
					this.initCipherEncrypt((McElieceCCA2PublicKeyParameters)key);
				}
			}
			else
			{
				this.key = (McElieceCCA2PrivateKeyParameters)param;
				this.initCipherDecrypt((McElieceCCA2PrivateKeyParameters)key);
			}

		}

		/// <summary>
		/// Return the key size of the given key object.
		/// </summary>
		/// <param name="key"> the McElieceCCA2KeyParameters object </param>
		/// <returns> the key size of the given key object </returns>
		/// <exception cref="IllegalArgumentException"> if the key is invalid </exception>
		public virtual int getKeySize(McElieceCCA2KeyParameters key)
		{

			if (key is McElieceCCA2PublicKeyParameters)
			{
				return ((McElieceCCA2PublicKeyParameters)key).getN();

			}
			if (key is McElieceCCA2PrivateKeyParameters)
			{
				return ((McElieceCCA2PrivateKeyParameters)key).getN();
			}
			throw new IllegalArgumentException("unsupported type");

		}


		public virtual int decryptOutputSize(int inLen)
		{
			return 0;
		}

		public virtual int encryptOutputSize(int inLen)
		{
			return 0;
		}


		private void initCipherEncrypt(McElieceCCA2PublicKeyParameters pubKey)
		{
			this.sr = sr != null ? sr : CryptoServicesRegistrar.getSecureRandom();
			this.messDigest = Utils.getDigest(pubKey.getDigest());
			n = pubKey.getN();
			k = pubKey.getK();
			t = pubKey.getT();
		}

		private void initCipherDecrypt(McElieceCCA2PrivateKeyParameters privKey)
		{
			this.messDigest = Utils.getDigest(privKey.getDigest());
			n = privKey.getN();
			k = privKey.getK();
			t = privKey.getT();
		}

		public virtual byte[] messageEncrypt(byte[] input)
		{
			if (!forEncryption)
			{
				throw new IllegalStateException("cipher initialised for decryption");
			}

			int kDiv8 = k >> 3;

			// generate random r of length k div 8 bytes
			byte[] r = new byte[kDiv8];
			sr.nextBytes(r);

			// generate random vector r' of length k bits
			GF2Vector rPrime = new GF2Vector(k, sr);

			// convert r' to byte array
			byte[] rPrimeBytes = rPrime.getEncoded();

			// compute (input||r)
			byte[] mr = ByteUtils.concatenate(input, r);

			// compute H(input||r)
			messDigest.update(mr, 0, mr.Length);
			byte[] hmr = new byte[messDigest.getDigestSize()];
			messDigest.doFinal(hmr, 0);


			// convert H(input||r) to error vector z
			GF2Vector z = Conversions.encode(n, t, hmr);

			// compute c1 = E(rPrime, z)
			byte[] c1 = McElieceCCA2Primitives.encryptionPrimitive((McElieceCCA2PublicKeyParameters)key, rPrime, z).getEncoded();

			// get PRNG object
			DigestRandomGenerator sr0 = new DigestRandomGenerator(new SHA1Digest());

			// seed PRNG with r'
			sr0.addSeedMaterial(rPrimeBytes);

			// generate random c2
			byte[] c2 = new byte[input.Length + kDiv8];
			sr0.nextBytes(c2);

			// XOR with input
			for (int i = 0; i < input.Length; i++)
			{
				c2[i] ^= input[i];
			}
			// XOR with r
			for (int i = 0; i < kDiv8; i++)
			{
				c2[input.Length + i] ^= r[i];
			}

			// return (c1||c2)
			return ByteUtils.concatenate(c1, c2);
		}

		public virtual byte[] messageDecrypt(byte[] input)
		{
			if (forEncryption)
			{
				throw new IllegalStateException("cipher initialised for decryption");
			}

			int c1Len = (n + 7) >> 3;
			int c2Len = input.Length - c1Len;

			// split cipher text (c1||c2)
			byte[][] c1c2 = ByteUtils.split(input, c1Len);
			byte[] c1 = c1c2[0];
			byte[] c2 = c1c2[1];

			// decrypt c1 ...
			GF2Vector c1Vec = GF2Vector.OS2VP(n, c1);
			GF2Vector[] c1Dec = McElieceCCA2Primitives.decryptionPrimitive((McElieceCCA2PrivateKeyParameters)key, c1Vec);
			byte[] rPrimeBytes = c1Dec[0].getEncoded();
			// ... and obtain error vector z
			GF2Vector z = c1Dec[1];

			// get PRNG object
			DigestRandomGenerator sr0 = new DigestRandomGenerator(new SHA1Digest());

			// seed PRNG with r'
			sr0.addSeedMaterial(rPrimeBytes);

			// generate random sequence
			byte[] mrBytes = new byte[c2Len];
			sr0.nextBytes(mrBytes);

			// XOR with c2 to obtain (m||r)
			for (int i = 0; i < c2Len; i++)
			{
				mrBytes[i] ^= c2[i];
			}

			// compute H(m||r)
			messDigest.update(mrBytes, 0, mrBytes.Length);
			byte[] hmr = new byte[messDigest.getDigestSize()];
			messDigest.doFinal(hmr, 0);

			// compute Conv(H(m||r))
			c1Vec = Conversions.encode(n, t, hmr);

			// check that Conv(H(m||r)) = z
			if (!c1Vec.Equals(z))
			{
				throw new InvalidCipherTextException("Bad Padding: Invalid ciphertext.");
			}

			// split (m||r) to obtain m
			int kDiv8 = k >> 3;
			byte[][] mr = ByteUtils.split(mrBytes, c2Len - kDiv8);

			// return plain text m
			return mr[0];
		}


	}

}