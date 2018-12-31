using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.ntru
{

	using AsymmetricBlockCipher = org.bouncycastle.crypto.AsymmetricBlockCipher;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using CryptoServicesRegistrar = CryptoServicesRegistrar;
	using DataLengthException = org.bouncycastle.crypto.DataLengthException;
	using Digest = org.bouncycastle.crypto.Digest;
	using InvalidCipherTextException = org.bouncycastle.crypto.InvalidCipherTextException;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using DenseTernaryPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
	using IntegerPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
	using Polynomial = org.bouncycastle.pqc.math.ntru.polynomial.Polynomial;
	using ProductFormPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.ProductFormPolynomial;
	using SparseTernaryPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial;
	using TernaryPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.TernaryPolynomial;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Encrypts, decrypts data and generates key pairs.<br>
	/// The parameter p is hardcoded to 3.
	/// </summary>
	public class NTRUEngine : AsymmetricBlockCipher
	{
		private bool forEncryption;
		private NTRUEncryptionParameters @params;
		private NTRUEncryptionPublicKeyParameters pubKey;
		private NTRUEncryptionPrivateKeyParameters privKey;
		private SecureRandom random;

		/// <summary>
		/// Constructs a new instance with a set of encryption parameters.
		/// 
		/// </summary>
		public NTRUEngine()
		{
		}

		public virtual void init(bool forEncryption, CipherParameters parameters)
		{
			this.forEncryption = forEncryption;
			if (forEncryption)
			{
				if (parameters is ParametersWithRandom)
				{
					ParametersWithRandom p = (ParametersWithRandom)parameters;

					this.random = p.getRandom();
					this.pubKey = (NTRUEncryptionPublicKeyParameters)p.getParameters();
				}
				else
				{
					this.random = CryptoServicesRegistrar.getSecureRandom();
					this.pubKey = (NTRUEncryptionPublicKeyParameters)parameters;
				}

				this.@params = pubKey.getParameters();
			}
			else
			{
				this.privKey = (NTRUEncryptionPrivateKeyParameters)parameters;
				this.@params = privKey.getParameters();
			}
		}

		public virtual int getInputBlockSize()
		{
			return @params.maxMsgLenBytes;
		}

		public virtual int getOutputBlockSize()
		{
			return ((@params.N * log2(@params.q)) + 7) / 8;
		}

		public virtual byte[] processBlock(byte[] @in, int inOff, int len)
		{
			byte[] tmp = new byte[len];

			JavaSystem.arraycopy(@in, inOff, tmp, 0, len);

			if (forEncryption)
			{
				return encrypt(tmp, pubKey);
			}
			else
			{
				return decrypt(tmp, privKey);
			}
		}

		/// <summary>
		/// Encrypts a message.<br/>
		/// See P1363.1 section 9.2.2.
		/// </summary>
		/// <param name="m">      The message to encrypt </param>
		/// <param name="pubKey"> the public key to encrypt the message with </param>
		/// <returns> the encrypted message </returns>
		private byte[] encrypt(byte[] m, NTRUEncryptionPublicKeyParameters pubKey)
		{
			IntegerPolynomial pub = pubKey.h;
			int N = @params.N;
			int q = @params.q;

			int maxLenBytes = @params.maxMsgLenBytes;
			int db = @params.db;
			int bufferLenBits = @params.bufferLenBits;
			int dm0 = @params.dm0;
			int pkLen = @params.pkLen;
			int minCallsMask = @params.minCallsMask;
			bool hashSeed = @params.hashSeed;
			byte[] oid = @params.oid;

			int l = m.Length;
			if (maxLenBytes > 255)
			{
				throw new IllegalArgumentException("llen values bigger than 1 are not supported");
			}
			if (l > maxLenBytes)
			{
				throw new DataLengthException("Message too long: " + l + ">" + maxLenBytes);
			}

			while (true)
			{
				// M = b|octL|m|p0
				byte[] b = new byte[db / 8];
				random.nextBytes(b);
				byte[] p0 = new byte[maxLenBytes + 1 - l];
				byte[] M = new byte[bufferLenBits / 8];

				JavaSystem.arraycopy(b, 0, M, 0, b.Length);
				M[b.Length] = (byte)l;
				JavaSystem.arraycopy(m, 0, M, b.Length + 1, m.Length);
				JavaSystem.arraycopy(p0, 0, M, b.Length + 1 + m.Length, p0.Length);

				IntegerPolynomial mTrin = IntegerPolynomial.fromBinary3Sves(M, N);

				// sData = OID|m|b|hTrunc
				byte[] bh = pub.toBinary(q);
				byte[] hTrunc = copyOf(bh, pkLen / 8);
				byte[] sData = buildSData(oid, m, l, b, hTrunc);

				Polynomial r = generateBlindingPoly(sData, M);
				IntegerPolynomial R = r.mult(pub, q);
				IntegerPolynomial R4 = (IntegerPolynomial)R.clone();
				R4.modPositive(4);
				byte[] oR4 = R4.toBinary(4);
				IntegerPolynomial mask = MGF(oR4, N, minCallsMask, hashSeed);
				mTrin.add(mask);
				mTrin.mod3();

				if (mTrin.count(-1) < dm0)
				{
					continue;
				}
				if (mTrin.count(0) < dm0)
				{
					continue;
				}
				if (mTrin.count(1) < dm0)
				{
					continue;
				}

				R.add(mTrin, q);
				R.ensurePositive(q);
				return R.toBinary(q);
			}
		}

		private byte[] buildSData(byte[] oid, byte[] m, int l, byte[] b, byte[] hTrunc)
		{
			byte[] sData = new byte[oid.Length + l + b.Length + hTrunc.Length];

			JavaSystem.arraycopy(oid, 0, sData, 0, oid.Length);
			JavaSystem.arraycopy(m, 0, sData, oid.Length, m.Length);
			JavaSystem.arraycopy(b, 0, sData, oid.Length + m.Length, b.Length);
			JavaSystem.arraycopy(hTrunc, 0, sData, oid.Length + m.Length + b.Length, hTrunc.Length);
			return sData;
		}

		public virtual IntegerPolynomial encrypt(IntegerPolynomial m, TernaryPolynomial r, IntegerPolynomial pubKey)
		{
			IntegerPolynomial e = r.mult(pubKey, @params.q);
			e.add(m, @params.q);
			e.ensurePositive(@params.q);
			return e;
		}

		/// <summary>
		/// Deterministically generates a blinding polynomial from a seed and a message representative.
		/// </summary>
		/// <param name="seed"> </param>
		/// <param name="M">    message representative </param>
		/// <returns> a blinding polynomial </returns>
		private Polynomial generateBlindingPoly(byte[] seed, byte[] M)
		{
			IndexGenerator ig = new IndexGenerator(seed, @params);

			if (@params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_PRODUCT)
			{
				SparseTernaryPolynomial r1 = new SparseTernaryPolynomial(generateBlindingCoeffs(ig, @params.dr1));
				SparseTernaryPolynomial r2 = new SparseTernaryPolynomial(generateBlindingCoeffs(ig, @params.dr2));
				SparseTernaryPolynomial r3 = new SparseTernaryPolynomial(generateBlindingCoeffs(ig, @params.dr3));
				return new ProductFormPolynomial(r1, r2, r3);
			}
			else
			{
				int dr = @params.dr;
				bool sparse = @params.sparse;
				int[] r = generateBlindingCoeffs(ig, dr);
				if (sparse)
				{
					return new SparseTernaryPolynomial(r);
				}
				else
				{
					return new DenseTernaryPolynomial(r);
				}
			}
		}

		/// <summary>
		/// Generates an <code>int</code> array containing <code>dr</code> elements equal to <code>1</code>
		/// and <code>dr</code> elements equal to <code>-1</code> using an index generator.
		/// </summary>
		/// <param name="ig"> an index generator </param>
		/// <param name="dr"> number of ones / negative ones </param>
		/// <returns> an array containing numbers between <code>-1</code> and <code>1</code> </returns>
		private int[] generateBlindingCoeffs(IndexGenerator ig, int dr)
		{
			int N = @params.N;

			int[] r = new int[N];
			for (int coeff = -1; coeff <= 1; coeff += 2)
			{
				int t = 0;
				while (t < dr)
				{
					int i = ig.nextIndex();
					if (r[i] == 0)
					{
						r[i] = coeff;
						t++;
					}
				}
			}

			return r;
		}

		/// <summary>
		/// An implementation of MGF-TP-1 from P1363.1 section 8.4.1.1.
		/// </summary>
		/// <param name="seed"> </param>
		/// <param name="N"> </param>
		/// <param name="minCallsR"> </param>
		/// <param name="hashSeed">  whether to hash the seed </param>
		private IntegerPolynomial MGF(byte[] seed, int N, int minCallsR, bool hashSeed)
		{
			Digest hashAlg = @params.hashAlg;
			int hashLen = hashAlg.getDigestSize();
			byte[] buf = new byte[minCallsR * hashLen];
			byte[] Z = hashSeed ? calcHash(hashAlg, seed) : seed;
			int counter = 0;
			while (counter < minCallsR)
			{
				hashAlg.update(Z, 0, Z.Length);
				putInt(hashAlg, counter);

				byte[] hash = calcHash(hashAlg);
				JavaSystem.arraycopy(hash, 0, buf, counter * hashLen, hashLen);
				counter++;
			}

			IntegerPolynomial i = new IntegerPolynomial(N);
			while (true)
			{
				int cur = 0;
				for (int index = 0; index != buf.Length; index++)
				{
					int O = buf[index] & 0xFF;
					if (O >= 243) // 243 = 3^5
					{
						continue;
					}

					for (int terIdx = 0; terIdx < 4; terIdx++)
					{
						int rem3 = O % 3;
						i.coeffs[cur] = rem3 - 1;
						cur++;
						if (cur == N)
						{
							return i;
						}
						O = (O - rem3) / 3;
					}

					i.coeffs[cur] = O - 1;
					cur++;
					if (cur == N)
					{
						return i;
					}
				}

				if (cur >= N)
				{
					return i;
				}

				hashAlg.update(Z, 0, Z.Length);
				putInt(hashAlg, counter);

				byte[] hash = calcHash(hashAlg);

				buf = hash;

				counter++;
			}
		}

		private void putInt(Digest hashAlg, int counter)
		{
			hashAlg.update((byte)(counter >> 24));
			hashAlg.update((byte)(counter >> 16));
			hashAlg.update((byte)(counter >> 8));
			hashAlg.update((byte)counter);
		}

		private byte[] calcHash(Digest hashAlg)
		{
			byte[] tmp = new byte[hashAlg.getDigestSize()];

			hashAlg.doFinal(tmp, 0);

			return tmp;
		}

		private byte[] calcHash(Digest hashAlg, byte[] input)
		{
			byte[] tmp = new byte[hashAlg.getDigestSize()];

			hashAlg.update(input, 0, input.Length);
			hashAlg.doFinal(tmp, 0);

			return tmp;
		}
		/// <summary>
		/// Decrypts a message.<br/>
		/// See P1363.1 section 9.2.3.
		/// </summary>
		/// <param name="data"> The message to decrypt </param>
		/// <param name="privKey">   the corresponding private key </param>
		/// <returns> the decrypted message </returns>
		/// <exception cref="InvalidCipherTextException"> if  the encrypted data is invalid, or <code>maxLenBytes</code> is greater than 255 </exception>
		private byte[] decrypt(byte[] data, NTRUEncryptionPrivateKeyParameters privKey)
		{
			Polynomial priv_t = privKey.t;
			IntegerPolynomial priv_fp = privKey.fp;
			IntegerPolynomial pub = privKey.h;
			int N = @params.N;
			int q = @params.q;
			int db = @params.db;
			int maxMsgLenBytes = @params.maxMsgLenBytes;
			int dm0 = @params.dm0;
			int pkLen = @params.pkLen;
			int minCallsMask = @params.minCallsMask;
			bool hashSeed = @params.hashSeed;
			byte[] oid = @params.oid;

			if (maxMsgLenBytes > 255)
			{
				throw new DataLengthException("maxMsgLenBytes values bigger than 255 are not supported");
			}

			int bLen = db / 8;

			IntegerPolynomial e = IntegerPolynomial.fromBinary(data, N, q);
			IntegerPolynomial ci = decrypt(e, priv_t, priv_fp);

			if (ci.count(-1) < dm0)
			{
				throw new InvalidCipherTextException("Less than dm0 coefficients equal -1");
			}
			if (ci.count(0) < dm0)
			{
				throw new InvalidCipherTextException("Less than dm0 coefficients equal 0");
			}
			if (ci.count(1) < dm0)
			{
				throw new InvalidCipherTextException("Less than dm0 coefficients equal 1");
			}

			IntegerPolynomial cR = (IntegerPolynomial)e.clone();
			cR.sub(ci);
			cR.modPositive(q);
			IntegerPolynomial cR4 = (IntegerPolynomial)cR.clone();
			cR4.modPositive(4);
			byte[] coR4 = cR4.toBinary(4);
			IntegerPolynomial mask = MGF(coR4, N, minCallsMask, hashSeed);
			IntegerPolynomial cMTrin = ci;
			cMTrin.sub(mask);
			cMTrin.mod3();
			byte[] cM = cMTrin.toBinary3Sves();

			byte[] cb = new byte[bLen];
			JavaSystem.arraycopy(cM, 0, cb, 0, bLen);
			int cl = cM[bLen] & 0xFF; // llen=1, so read one byte
			if (cl > maxMsgLenBytes)
			{
				throw new InvalidCipherTextException("Message too long: " + cl + ">" + maxMsgLenBytes);
			}
			byte[] cm = new byte[cl];
			JavaSystem.arraycopy(cM, bLen + 1, cm, 0, cl);
			byte[] p0 = new byte[cM.Length - (bLen + 1 + cl)];
			JavaSystem.arraycopy(cM, bLen + 1 + cl, p0, 0, p0.Length);
			if (!Arrays.constantTimeAreEqual(p0, new byte[p0.Length]))
			{
			   throw new InvalidCipherTextException("The message is not followed by zeroes");
			}

			// sData = OID|m|b|hTrunc
			byte[] bh = pub.toBinary(q);
			byte[] hTrunc = copyOf(bh, pkLen / 8);
			byte[] sData = buildSData(oid, cm, cl, cb, hTrunc);

			Polynomial cr = generateBlindingPoly(sData, cm);
			IntegerPolynomial cRPrime = cr.mult(pub);
			cRPrime.modPositive(q);
			if (!cRPrime.Equals(cR))
			{
				throw new InvalidCipherTextException("Invalid message encoding");
			}

			return cm;
		}

		/// <param name="e"> </param>
		/// <param name="priv_t">  a polynomial such that if <code>fastFp=true</code>, <code>f=1+3*priv_t</code>; otherwise, <code>f=priv_t</code> </param>
		/// <param name="priv_fp"> </param>
		/// <returns> an IntegerPolynomial representing the output. </returns>
		public virtual IntegerPolynomial decrypt(IntegerPolynomial e, Polynomial priv_t, IntegerPolynomial priv_fp)
		{
			IntegerPolynomial a;
			if (@params.fastFp)
			{
				a = priv_t.mult(e, @params.q);
				a.mult(3);
				a.add(e);
			}
			else
			{
				a = priv_t.mult(e, @params.q);
			}
			a.center0(@params.q);
			a.mod3();

			IntegerPolynomial c = @params.fastFp ? a : (new DenseTernaryPolynomial(a)).mult(priv_fp, 3);
			c.center0(3);
			return c;
		}

		private byte[] copyOf(byte[] src, int len)
		{
			byte[] tmp = new byte[len];

			JavaSystem.arraycopy(src, 0, tmp, 0, len < src.Length ? len : src.Length);

			return tmp;
		}

		private int log2(int value)
		{
			if (value == 2048)
			{
				return 11;
			}

			throw new IllegalStateException("log2 not fully implemented");
		}
	}
}