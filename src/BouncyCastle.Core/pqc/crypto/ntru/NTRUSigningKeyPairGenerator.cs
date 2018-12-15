using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.pqc.crypto.ntru
{

	using AsymmetricCipherKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair;
	using AsymmetricCipherKeyPairGenerator = org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
	using CryptoServicesRegistrar = org.bouncycastle.crypto.CryptoServicesRegistrar;
	using KeyGenerationParameters = org.bouncycastle.crypto.KeyGenerationParameters;
	using BigIntEuclidean = org.bouncycastle.pqc.math.ntru.euclid.BigIntEuclidean;
	using BigDecimalPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.BigDecimalPolynomial;
	using BigIntPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.BigIntPolynomial;
	using DenseTernaryPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
	using IntegerPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;
	using Polynomial = org.bouncycastle.pqc.math.ntru.polynomial.Polynomial;
	using ProductFormPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.ProductFormPolynomial;
	using Resultant = org.bouncycastle.pqc.math.ntru.polynomial.Resultant;


	public class NTRUSigningKeyPairGenerator : AsymmetricCipherKeyPairGenerator
	{
		private NTRUSigningKeyGenerationParameters @params;

		public virtual void init(KeyGenerationParameters param)
		{
			this.@params = (NTRUSigningKeyGenerationParameters)param;
		}

		/// <summary>
		/// Generates a new signature key pair. Starts <code>B+1</code> threads.
		/// </summary>
		/// <returns> a key pair </returns>
		public virtual AsymmetricCipherKeyPair generateKeyPair()
		{
			NTRUSigningPublicKeyParameters pub = null;
			ExecutorService executor = Executors.newCachedThreadPool();
			List<Future<NTRUSigningPrivateKeyParameters.Basis>> bases = new ArrayList<Future<NTRUSigningPrivateKeyParameters.Basis>>();
			for (int k = @params.B; k >= 0; k--)
			{
				bases.add(executor.submit(new BasisGenerationTask(this)));
			}
			executor.shutdown();

			List<NTRUSigningPrivateKeyParameters.Basis> basises = new ArrayList<NTRUSigningPrivateKeyParameters.Basis>();

			for (int k = @params.B; k >= 0; k--)
			{
				Future<NTRUSigningPrivateKeyParameters.Basis> basis = bases.get(k);
				try
				{
					basises.add(basis.get());
					if (k == @params.B)
					{
						pub = new NTRUSigningPublicKeyParameters(basis.get().h, @params.getSigningParameters());
					}
				}
				catch (Exception e)
				{
					throw new IllegalStateException(e);
				}
			}
			NTRUSigningPrivateKeyParameters priv = new NTRUSigningPrivateKeyParameters(basises, pub);
			AsymmetricCipherKeyPair kp = new AsymmetricCipherKeyPair(pub, priv);
			return kp;
		}

		/// <summary>
		/// Generates a new signature key pair. Runs in a single thread.
		/// </summary>
		/// <returns> a key pair </returns>
		public virtual AsymmetricCipherKeyPair generateKeyPairSingleThread()
		{
			List<NTRUSigningPrivateKeyParameters.Basis> basises = new ArrayList<NTRUSigningPrivateKeyParameters.Basis>();
			NTRUSigningPublicKeyParameters pub = null;
			for (int k = @params.B; k >= 0; k--)
			{
				NTRUSigningPrivateKeyParameters.Basis basis = generateBoundedBasis();
				basises.add(basis);
				if (k == 0)
				{
					pub = new NTRUSigningPublicKeyParameters(basis.h, @params.getSigningParameters());
				}
			}
			NTRUSigningPrivateKeyParameters priv = new NTRUSigningPrivateKeyParameters(basises, pub);
			return new AsymmetricCipherKeyPair(pub, priv);
		}


		/*
		 * Implementation of the optional steps 20 through 26 in EESS1v2.pdf, section 3.5.1.1.
		 * This doesn't seem to have much of an effect and sometimes actually increases the
		 * norm of F, but on average it slightly reduces the norm.<br/>
		 * This method changes <code>F</code> and <code>g</code> but leaves <code>f</code> and
		 * <code>g</code> unchanged.
		 */
		private void minimizeFG(IntegerPolynomial f, IntegerPolynomial g, IntegerPolynomial F, IntegerPolynomial G, int N)
		{
			int E = 0;
			for (int j = 0; j < N; j++)
			{
				E += 2 * N * (f.coeffs[j] * f.coeffs[j] + g.coeffs[j] * g.coeffs[j]);
			}

			// [f(1)+g(1)]^2 = 4
			E -= 4;

			IntegerPolynomial u = (IntegerPolynomial)f.clone();
			IntegerPolynomial v = (IntegerPolynomial)g.clone();
			int j = 0;
			int k = 0;
			int maxAdjustment = N;
			while (k < maxAdjustment && j < N)
			{
				int D = 0;
				int i = 0;
				while (i < N)
				{
				    {int D1 = F.coeffs[i] * f.coeffs[i];
					int D2 = G.coeffs[i] * g.coeffs[i];
					int D3 = 4 * N * (D1 + D2);
					D += D3;
					i++;
				    }
                }
                // f(1)+g(1) = 2
			    { int D1 = 4 * (F.sumCoeffs() + G.sumCoeffs());
				D -= D1;

				if (D > E)
				{
					F.sub(u);
					G.sub(v);
					k++;
					j = 0;
				}
				else if (D < -E)
				{
					F.add(u);
					G.add(v);
					k++;
					j = 0;
				}
				j++;
				u.rotate1();
				v.rotate1();
			    }
            }
		}

		/// <summary>
		/// Creates a NTRUSigner basis consisting of polynomials <code>f, g, F, G, h</code>.<br/>
		/// If <code>KeyGenAlg=FLOAT</code>, the basis may not be valid and this method must be rerun if that is the case.<br/>
		/// </summary>
		/// <seealso cref= #generateBoundedBasis() </seealso>
		private FGBasis generateBasis()
		{
			int N = @params.N;
			int q = @params.q;
			int d = @params.d;
			int d1 = @params.d1;
			int d2 = @params.d2;
			int d3 = @params.d3;
			int basisType = @params.basisType;

			Polynomial f;
			IntegerPolynomial fInt;
			Polynomial g;
			IntegerPolynomial gInt;
			IntegerPolynomial fq;
			Resultant rf;
			Resultant rg;
			BigIntEuclidean r;

			int _2n1 = 2 * N + 1;
			bool primeCheck = @params.primeCheck;

			do
			{
				do
				{
					f = @params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE ? DenseTernaryPolynomial.generateRandom(N, d + 1, d, CryptoServicesRegistrar.getSecureRandom()) : ProductFormPolynomial.generateRandom(N, d1, d2, d3 + 1, d3, CryptoServicesRegistrar.getSecureRandom());
					fInt = f.toIntegerPolynomial();
				} while (primeCheck && fInt.resultant(_2n1).res.Equals(ZERO));
				fq = fInt.invertFq(q);
			} while (fq == null);
			rf = fInt.resultant();

			do
			{
				do
				{
					do
					{
						g = @params.polyType == NTRUParameters.TERNARY_POLYNOMIAL_TYPE_SIMPLE ? DenseTernaryPolynomial.generateRandom(N, d + 1, d, CryptoServicesRegistrar.getSecureRandom()) : ProductFormPolynomial.generateRandom(N, d1, d2, d3 + 1, d3, CryptoServicesRegistrar.getSecureRandom());
						gInt = g.toIntegerPolynomial();
					} while (primeCheck && gInt.resultant(_2n1).res.Equals(ZERO));
				} while (gInt.invertFq(q) == null);
				rg = gInt.resultant();
				r = BigIntEuclidean.calculate(rf.res, rg.res);
			} while (!r.gcd.Equals(ONE));

			BigIntPolynomial A = (BigIntPolynomial)rf.rho.clone();
			A.mult(r.x.multiply(BigInteger.valueOf(q)));
			BigIntPolynomial B = (BigIntPolynomial)rg.rho.clone();
			B.mult(r.y.multiply(BigInteger.valueOf(-q)));

			BigIntPolynomial C;
			if (@params.keyGenAlg == NTRUSigningKeyGenerationParameters.KEY_GEN_ALG_RESULTANT)
			{
				int[] fRevCoeffs = new int[N];
				int[] gRevCoeffs = new int[N];
				fRevCoeffs[0] = fInt.coeffs[0];
				gRevCoeffs[0] = gInt.coeffs[0];
				for (int i = 1; i < N; i++)
				{
					fRevCoeffs[i] = fInt.coeffs[N - i];
					gRevCoeffs[i] = gInt.coeffs[N - i];
				}
				IntegerPolynomial fRev = new IntegerPolynomial(fRevCoeffs);
				IntegerPolynomial gRev = new IntegerPolynomial(gRevCoeffs);

				IntegerPolynomial t = f.mult(fRev);
				t.add(g.mult(gRev));
				Resultant rt = t.resultant();
				C = fRev.mult(B); // fRev.mult(B) is actually faster than new SparseTernaryPolynomial(fRev).mult(B), possibly due to cache locality?
				C.add(gRev.mult(A));
				C = C.mult(rt.rho);
				C.div(rt.res);
			}
			else
			{ // KeyGenAlg.FLOAT
				// calculate ceil(log10(N))
				int log10N = 0;
				for (int i = 1; i < N; i *= 10)
				{
					log10N++;
				}

				// * Cdec needs to be accurate to 1 decimal place so it can be correctly rounded;
				// * fInv loses up to (#digits of longest coeff of B) places in fInv.mult(B);
				// * multiplying fInv by B also multiplies the rounding error by a factor of N;
				// so make #decimal places of fInv the sum of the above.
				BigDecimalPolynomial fInv = rf.rho.div(new BigDecimal(rf.res), B.getMaxCoeffLength() + 1 + log10N);
				BigDecimalPolynomial gInv = rg.rho.div(new BigDecimal(rg.res), A.getMaxCoeffLength() + 1 + log10N);

				BigDecimalPolynomial Cdec = fInv.mult(B);
				Cdec.add(gInv.mult(A));
				Cdec.halve();
				C = Cdec.round();
			}

			BigIntPolynomial F = (BigIntPolynomial)B.clone();
			F.sub(f.mult(C));
			BigIntPolynomial G = (BigIntPolynomial)A.clone();
			G.sub(g.mult(C));

			IntegerPolynomial FInt = new IntegerPolynomial(F);
			IntegerPolynomial GInt = new IntegerPolynomial(G);
			minimizeFG(fInt, gInt, FInt, GInt, N);

			Polynomial fPrime;
			IntegerPolynomial h;
			if (basisType == NTRUSigningKeyGenerationParameters.BASIS_TYPE_STANDARD)
			{
				fPrime = FInt;
				h = g.mult(fq, q);
			}
			else
			{
				fPrime = g;
				h = FInt.mult(fq, q);
			}
			h.modPositive(q);

			return new FGBasis(this, f, fPrime, h, FInt, GInt, @params);
		}

		/// <summary>
		/// Creates a basis such that <code>|F| &lt; keyNormBound</code> and <code>|G| &lt; keyNormBound</code>
		/// </summary>
		/// <returns> a NTRUSigner basis </returns>
		public virtual NTRUSigningPrivateKeyParameters.Basis generateBoundedBasis()
		{
			while (true)
			{
				FGBasis basis = generateBasis();
				if (basis.isNormOk())
				{
					return basis;
				}
			}
		}

		public class BasisGenerationTask : Callable<NTRUSigningPrivateKeyParameters.Basis>
		{
			private readonly NTRUSigningKeyPairGenerator outerInstance;

			public BasisGenerationTask(NTRUSigningKeyPairGenerator outerInstance)
			{
				this.outerInstance = outerInstance;
			}



			public virtual NTRUSigningPrivateKeyParameters.Basis call()
			{
				return outerInstance.generateBoundedBasis();
			}
		}

		/// <summary>
		/// A subclass of Basis that additionally contains the polynomials <code>F</code> and <code>G</code>.
		/// </summary>
		public class FGBasis : NTRUSigningPrivateKeyParameters.Basis
		{
			private readonly NTRUSigningKeyPairGenerator outerInstance;

			public IntegerPolynomial F;
			public IntegerPolynomial G;

			public FGBasis(NTRUSigningKeyPairGenerator outerInstance, Polynomial f, Polynomial fPrime, IntegerPolynomial h, IntegerPolynomial F, IntegerPolynomial G, NTRUSigningKeyGenerationParameters @params) : base(f, fPrime, h, @params)
			{
				this.outerInstance = outerInstance;
				this.F = F;
				this.G = G;
			}

			/*
			 * Returns <code>true</code> if the norms of the polynomials <code>F</code> and <code>G</code>
			 * are within {@link NTRUSigningKeyGenerationParameters#keyNormBound}.
			 */
			public virtual bool isNormOk()
			{
				double keyNormBoundSq = @params.keyNormBoundSq;
				int q = @params.q;
				return (F.centeredNormSq(q) < keyNormBoundSq && G.centeredNormSq(q) < keyNormBoundSq);
			}
		}
	}

}