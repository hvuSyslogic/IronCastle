﻿namespace org.bouncycastle.pqc.crypto.ntru
{
	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using AsymmetricCipherKeyPairGenerator = org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;
	using DenseTernaryPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
	using IntegerPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
	using Polynomial = org.bouncycastle.pqc.math.ntru.polynomial.Polynomial;
	using ProductFormPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.ProductFormPolynomial;
	using Util = org.bouncycastle.pqc.math.ntru.util.Util;

	/// <summary>
	/// Generates key pairs.<br>
	/// The parameter p is hardcoded to 3.
	/// </summary>
	public class NTRUEncryptionKeyPairGenerator : AsymmetricCipherKeyPairGenerator
	{
		private NTRUEncryptionKeyGenerationParameters @params;

		/// <summary>
		/// Constructs a new instance with a set of encryption parameters.
		/// </summary>
		/// <param name="param"> encryption parameters </param>
		public virtual void init(KeyGenerationParameters param)
		{
			this.@params = (NTRUEncryptionKeyGenerationParameters)param;
		}

		/// <summary>
		/// Generates a new encryption key pair.
		/// </summary>
		/// <returns> a key pair </returns>
		public virtual AsymmetricCipherKeyPair generateKeyPair()
		{
			int N = @params.N;
			int q = @params.q;
			int df = @params.df;
			int df1 = @params.df1;
			int df2 = @params.df2;
			int df3 = @params.df3;
			int dg = @params.dg;
			bool fastFp = @params.fastFp;
			bool sparse = @params.sparse;

			Polynomial t;
			IntegerPolynomial fq;
			IntegerPolynomial fp = null;

			// choose a random f that is invertible mod 3 and q
			while (true)
			{
				IntegerPolynomial f;

				// choose random t, calculate f and fp
				if (fastFp)
				{
					// if fastFp=true, f is always invertible mod 3
					t = @params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE ? (Polynomial) Util.generateRandomTernary(N, df, df, sparse, @params.getRandom()) : ProductFormPolynomial.generateRandom(N, df1, df2, df3, df3, @params.getRandom());
					f = t.toIntegerPolynomial();
					f.mult(3);
					f.coeffs[0] += 1;
				}
				else
				{
					t = @params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE ? (Polynomial) Util.generateRandomTernary(N, df, df - 1, sparse, @params.getRandom()) : ProductFormPolynomial.generateRandom(N, df1, df2, df3, df3 - 1, @params.getRandom());
					f = t.toIntegerPolynomial();
					fp = f.invertF3();
					if (fp == null)
					{
						continue;
					}
				}

				fq = f.invertFq(q);
				if (fq == null)
				{
					continue;
				}
				break;
			}

			// if fastFp=true, fp=1
			if (fastFp)
			{
				fp = new IntegerPolynomial(N);
				fp.coeffs[0] = 1;
			}

			// choose a random g that is invertible mod q
			DenseTernaryPolynomial g;
			while (true)
			{
				g = DenseTernaryPolynomial.generateRandom(N, dg, dg - 1, @params.getRandom());
				if (g.invertFq(q) != null)
				{
					break;
				}
			}

			IntegerPolynomial h = g.mult(fq, q);
			h.mult3(q);
			h.ensurePositive(q);
			g.clear();
			fq.clear();

			NTRUEncryptionPrivateKeyParameters priv = new NTRUEncryptionPrivateKeyParameters(h, t, fp, @params.getEncryptionParameters());
			NTRUEncryptionPublicKeyParameters pub = new NTRUEncryptionPublicKeyParameters(h, @params.getEncryptionParameters());
			return new AsymmetricCipherKeyPair(pub, priv);
		}
	}
}